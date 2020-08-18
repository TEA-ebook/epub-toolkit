import cheerio from 'cheerio';
import {hash} from 'rsvp';
import Lcp from './Lcp';
import {isEmpty, parseXml, normalizePath, getOpfFilePath, getBasePath, getDirPath} from './utils';
import mime from 'mime-types';
import forge from 'node-forge';

class ZipEpub  {
  constructor(zip, license, userKey) {
    this.zip = zip;
    this.license = license;
    this.userKey = userKey;

    this.uid = null;
    this.metadata = null;
    this.protectedFiles = null;
  }

  async getMetadata() {
    if (!this.metadata) {
      this.metadata = await getMetadata(this.zip);
    }
    return this.metadata;
  }

  getCoverPath() {
    return getCoverPath(this.zip);
  }

  async getProtectedFiles() {
    if (!this.protectedFiles) {
      this.protectedFiles = await getProtectedFiles(this.zip);
    }
    return this.protectedFiles;
  }

  async getUid() {
    if (this.uid === null) {
      const metadata = await getMetadata(this.zip);
      this.uid = metadata['dc:identifier'] || 0;
    }
    return this.uid;
  }

  async getFileProtection(path) {
    const protections = await getProtectedFiles(this.zip);
    return protections[path];
  }

  async getFile(path) {
    const zipFile = this.zip.file(path);
    if (!zipFile) {
      return;
    }

    const contentType = mime.contentType(path.split('/').pop());

    return {
      data: await getZipFileData(zipFile, contentType, await this.getFileProtection(path), this.license, this.userKey, await this.getUid()),
      contentType
    };
  }
}

export default ZipEpub;


const BYTES_FORMAT = 'uint8array';
const STRING_FORMAT = 'string';

const ENCRYPTION_METHODS = {
  IDPF: 'http://www.idpf.org/2008/embedding',
  ADOBE: 'http://ns.adobe.com/pdf/enc#RC',
  LCP: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'
};

async function getZipFileData(zipFile, contentType, protection, license, userKey, uid) {
  const fetchMode = getFetchModeFromMimeType(contentType);
  if (!protection) {
    return zipFile.async(fetchMode);
  }
  switch (protection.algorithm) {
    case ENCRYPTION_METHODS.LCP:
      const decodedData = await Lcp.decipherFile(fetchMode, await zipFile.async('arraybuffer'), protection, license, userKey);
      if (fetchMode === 'text') {
        return fixDecodedTextData(decodedData, contentType);
      }
      return decodedData;

    case ENCRYPTION_METHODS.IDPF:
      // not implemented yet
      return zipFile.async(fetchMode);

    case ENCRYPTION_METHODS.ADOBE:
      // not implemented yet
      return zipFile.async(fetchMode);
  }
}

async function getFile(zip, path, format = STRING_FORMAT) {
  const zipFile = zip.file(normalizePath(path));
  if (!zipFile) {
    throw new Error(`file ${path} not found in zip`);
  }

  return zipFile.async(format);
}

function getOpfContent(zip) {
  let basePath;

  return getFile(zip, 'META-INF/container.xml', BYTES_FORMAT)
  // finding .opf path in container.xml
    .then(parseXml)
    .then(document => {
      const opfFilePath = getOpfFilePath(document);
      basePath = getBasePath(opfFilePath);
      return getFile(zip, opfFilePath);
    })
    .then(opfXml => {
      return hash({
        basePath: basePath,
        opf: parseXml(opfXml.trim())
      }, 'opf-data');
    });
}

function getMetadata(zip) {
  return getOpfContent(zip)
    .then(({opf}) => {
      const fixedMetadata = {};
      const metadata = opf('metadata > *');
      const uniqueIdentifier = opf('package').attr('unique-identifier');

      metadata.each((index, entry) => {
        const data = extractMetadataEntry(entry);
        if (fixedMetadata[data.key] && data.key === 'dc:identifier' && entry.attribs['id'] !== uniqueIdentifier) {
          return;
        }
        fixedMetadata[data.key] = data.value;
      });
      return fixedMetadata;
    });
}

function getCoverPath(zip) {
  return getOpfContent(zip)
    .then(({basePath, opf}) => getCoverFilePath(zip, opf, basePath));
}

function getCoverFilePath(zip, opf, basePath) {
  return new Promise((resolve, reject) => {
    // method 1: search for meta cover
    getCoverFilePathFromMetaCover(opf, basePath)
      .then(resolve)

      // method 2: search for an item in manifest with cover-image property
      .catch(() => getCoverFilePathFromManifestItem(opf, basePath))
      .then(resolve)

      // method 3 : search for a reference in the guide
      .catch(() => getCoverFilePathFromGuide(opf, basePath, zip))
      .then(resolve)

      // method 4 : browse 3 first items of the spine
      .catch(() => getCoverFilePathFromSpineItems(opf, basePath, zip))
      .then(resolve)

      .catch(reject);
  });
}

function getImagePathFromXhtml(xhtml) {
  const coverPage = cheerio.load(xhtml);

  const coverImg = coverPage('img');
  if (!isEmpty(coverImg)) {
    return coverImg.attr('src');
  }

  const coverImage = coverPage('image');
  if (!isEmpty(coverImage)) {
    return coverImage.attr('href');
  }
}

function getCoverFilePathFromMetaCover(opf, basePath) {
  return new Promise((resolve, reject) => {
    const coverItemRef = opf('metadata > meta[name="cover"]');
    if (!coverItemRef) {
      reject('no cover data found in metadata');
      return;
    }
    const coverItem = opf(`manifest > item[id='${coverItemRef.attr('content')}']`);
    if (isEmpty(coverItem)) {
      reject(`no item found in manifest with id ${coverItemRef.attr('content')}`);
      return;
    }
    resolve(basePath + coverItem.attr('href'));
  });
}

function getCoverFilePathFromManifestItem(opf, basePath) {
  return new Promise((resolve, reject) => {
    const coverItem = opf('manifest > item[properties="cover-image"]');
    if (isEmpty(coverItem)) {
      reject('no item with properties "cover-image" found in manifest');
      return;
    }
    resolve(basePath + coverItem.attr('href'));
  });
}

function getCoverFilePathFromGuide(opf, basePath, zip) {
  return new Promise((resolve, reject) => {
    const coverItem = opf('guide > reference[type="cover"]');
    if (isEmpty(coverItem)) {
      reject('no item of type "cover" found in guide');
      return;
    }

    const itemBasePath = basePath + getDirPath(coverItem.attr('href'));
    getFile(zip, basePath + coverItem.attr('href'))
      .then((coverPageXml) => {
        const coverPath = getImagePathFromXhtml(coverPageXml);
        if (coverPath) {
          resolve(itemBasePath + coverPath);
        } else {
          reject('no image url found in xhtml page');
        }
      });
  });
}

function getCoverFilePathFromSpineItems(opf, basePath, zip) {
  return new Promise((resolve, reject) => {
    const spineItems = opf('spine > itemref');
    if (isEmpty(spineItems)) {
      reject('no spine items found');
      return;
    }
    const idrefs = spineItems.slice(0, 3).map((index, item) => cheerio(item).attr('idref')).toArray();
    getCoverFilePathFromSpineItem(opf, basePath, zip, idrefs, resolve, reject);
  });
}

function getCoverFilePathFromSpineItem(opf, basePath, zip, idrefs, resolve, reject) {
  if (idrefs.length === 0) {
    reject('no spine item found with cover image inside');
    return;
  }

  const id = idrefs.shift();
  const item = opf(`manifest > item[id="${id}"]`);
  if (isEmpty(item) || !item.attr('href')) {
    reject(`no valid manifest item found with id ${id}`);
    return;
  }

  const spineItemBasePath = basePath + getDirPath(item.attr('href'));
  getFile(zip, basePath + item.attr('href')).then((itemXml) => {
    const coverPath = getImagePathFromXhtml(itemXml);
    if (coverPath) {
      resolve(spineItemBasePath + coverPath);
    } else {
      getCoverFilePathFromSpineItem(opf, basePath, zip, idrefs, resolve, reject);
    }
  });
}

async function getProtectedFiles(zip) {
  try {
    const xmlFile = await getFile(zip, 'META-INF/encryption.xml', STRING_FORMAT)
      .then(parseXml)
      .catch(() => {
        // no encryption.xml, so no protection
        return null;
      });

    if (xmlFile === null) {
      return {};
    }

    const resources = {};
    xmlFile('EncryptedData').each((index, element) => {
      const uri = xmlFile('CipherData > CipherReference', element).attr('URI');
      const algorithm = xmlFile('EncryptionMethod', element).attr('Algorithm');
      const compression = xmlFile('Compression', element);

      let type = null;
      const retrievalMethod = xmlFile('KeyInfo > RetrievalMethod', element);
      if (retrievalMethod.length > 0) {
        type = retrievalMethod.attr('Type');
      }
      const keyInfo = xmlFile('KeyInfo > resource', element);
      if (keyInfo.length > 0) {
        type = keyInfo.attr('xmlns');
      }

      resources[decodeURIComponent(uri)] = {
        algorithm,
        compressionMethod: compression ? parseInt(compression.attr('Method'), 10) : 0,
        originalLength: compression ? parseInt(compression.attr('OriginalLength'), 10) : 0,
        type
      };
    });

    return resources;
  } catch (error) {
    console.warn(error);
    throw error;
  }
}

function getFetchModeFromMimeType(mimeType) {
  if (mimeType.indexOf('image') !== -1) {
    return 'nodebuffer';
  }
  if (mimeType.indexOf('video') !== -1) {
    return 'nodebuffer';
  }
  if (mimeType.indexOf('font') !== -1) {
    return 'nodebuffer';
  }
  return 'text';
}

function fixDecodedTextData(decryptedBinaryData, mimeType) {
  if (typeof decryptedBinaryData !== 'string') {
    return decryptedBinaryData;
  }

  // BOM removal
  if (decryptedBinaryData.charCodeAt(0) === 0xFEFF) {
    decryptedBinaryData = decryptedBinaryData.substr(1);
  }
  let data = decryptedBinaryData.replace(/^ï»¿/, '');

  // convert UTF-8 decoded data to UTF-16 javascript string
  if (/html/.test(mimeType)) {
    try {
      data = forge.util.decodeUtf8(data);

      // trimming bad data at the end the spine
      var lastClosingTagIndex = data.lastIndexOf('>');
      if (lastClosingTagIndex > 0) {
        data = data.substring(0, lastClosingTagIndex + 1);
      }
    } catch (err) {
      console.warn('Can’t decode utf8 content', err);
    }
  }
  return data;
}

function extractMetadataEntry(entry) {
  const element = cheerio(entry);
  const tagName = entry.tagName;

  let key, value;

  if (tagName === 'meta') {
    key = element.attr('property');

    if (key) {
      value = element.text();
    } else {
      key = element.attr('name');
      value = element.attr('content');
    }
  } else {
    key = tagName;
    value = element.text();
  }

  return {key, value};
}
