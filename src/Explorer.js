const {all, allSettled, hash, resolve, reject, Promise} = require('rsvp');
const {isEmpty} = require('./utils');
const Lcp = require('./Lcp');
const JSZip = require('jszip');
const cheerio = require('cheerio');

const parseToc = require('./TocParser');

const UTF8 = 'utf-8';
const UTF16BE = 'utf-16be';
const UTF16LE = 'utf-16le';
const UTF32BE = 'utf-32be';
const UTF32LE = 'utf-32le';

const UTF16BE_BOM_MARKER = '254-255';
const UTF16LE_BOM_MARKER = '255-254';
const UTF32BE_BOM_MARKER = '0-0-254-255';
const UTF32LE_BOM_MARKER = '255-254-0-0';

const BYTES_FORMAT = 'uint8array';
const STRING_FORMAT = 'string';
const ARRAYBUFFER_FORMAT = 'arraybuffer';

const PROMISE_FULFILLED = 'fulfilled';

const EPUB_FILE_MIME_TYPE = 'application/epub+zip';
const ASCM_XML_ROOT_TAG = 'fulfillmentToken';

const EMPTY_ELEMENTS_COUNT = {characterCount: 0, imageCount: 0, videoCount: 0, totalCount: 0};

const PROTECTION_METHOD = {
  ADOBE_DRM: 'http://ns.adobe.com/adept',
  ADOBE_FONT: 'http://ns.adobe.com/pdf/enc#RC',
  LCP: 'license.lcpl#/encryption/content_key',
  IDPF_FONT: 'http://www.idpf.org/2008/embedding',
  UNKNOWN: 'unknown'
};

const ELEMENT_NODE = 1;
const TEXT_NODE = 3;

class Explorer {

  /**
   * Analyze and extracts infos from epub
   *
   * @param {UInt8Array} epubData: epub filename or epub binary data
   * @param userKeys: user LCP keys
   * @return {Promise} A promise that resolves extra data from the epub
   */
  analyze(epubData, userKeys = null) {
    return JSZip.loadAsync(epubData)
      .then(zip => {
        return allSettled([getMetadata(zip), getToc(zip)])
          .then(([metadataResult, tocResult]) => {
            const bookExtraData = {};
            if (metadataResult.state === PROMISE_FULFILLED) {
              bookExtraData.metadata = metadataResult.value;
            }
            if (tocResult.state === PROMISE_FULFILLED) {
              bookExtraData.toc = tocResult.value;
            }
            return bookExtraData;
          })
          .then(data => {
            return getSpines.call(this, zip, userKeys, data.toc)
              .then(spines => data.spines = spines)
              .then(() => computeTocItemsSizes(data.toc))
              .then(() => generatePagination(data.toc, data.spines))
              .then(pagination => {
                data.pagination = pagination;
                return data;
              })
          });
      });
  }

  /**
   * Get metadata from epub data
   *
   * @param {UInt8Array} epubData
   * @return {Promise} A promise that resolves with the metadata
   */
  metadata(epubData) {
    return JSZip.loadAsync(epubData).then(getMetadata);
  }

  /**
   * Get Table of Content from epub data
   *
   * @param {UInt8Array} epubData
   * @return {Promise} A promise that resolves with the table of content
   */
  toc(epubData) {
    return JSZip.loadAsync(epubData).then(getToc);
  }

  /**
   * Extracts cover image raw data from epub data
   *
   * @param {UInt8Array} epubData
   * @return {Promise} A promise that resolves with the image data
   */
  cover(epubData) {
    return JSZip.loadAsync(epubData).then(getCoverData);
  }

  /**
   * Extracts cover image path from epub data
   *
   * @param {UInt8Array} epubData
   * @return {Promise} A promise that resolves with the image path
   */
  coverPath(epubData) {
    return JSZip.loadAsync(epubData).then(getCoverPath);
  }

  /**
   * Get spines from epub data
   *
   * @param {UInt8Array} epubData
   * @param {Array} keys: User LCP keys
   * @return {Promise} A promise that resolves with an array of each spine character count
   */
  spines(epubData, keys = null) {
    return JSZip.loadAsync(epubData)
      .then(zip => getSpines.call(this, zip, keys));
  }

  /**
   * Extracts LCP license from epub
   *
   * @param {UInt8Array} epubData: epub binary data
   * @return {Promise} A promise that resolves with the parsed LCP license
   */
  lcpLicense(epubData) {
    return JSZip.loadAsync(epubData)
      .then(getLcpLicense);
  }

  /**
   * Extracts protections from epub
   *
   * @param {UInt8Array} epubData: epub binary data
   */
  protections(epubData) {
    return JSZip.loadAsync(epubData)
      .then(getProtections);
  }

  /**
   *
   * @param epub
   * @returns {*}
   */
  isValid(epubData) {
    return testEpubFileValidity(epubData);
  }

  /**
   *
   * @param epubData
   * @returns {*}
   */
  isAscmFile(epubData) {
    return isAscmFile(epubData);
  }
}

module.exports = new Explorer();


function getFile(zip, path, format = STRING_FORMAT) {
  console.log('getting file', path);
  const zipFile = zip.file(normalizePath(path));
  if (!zipFile) {
    return reject(`file ${path} not found in zip`);
  }

  return zipFile.async(format);
}

function getFileContent(zip, path, license, key) {
  const format = license ? ARRAYBUFFER_FORMAT : STRING_FORMAT;
  return getFile(zip, path, format)
    .then(fileContent => {
      if (license) {
        return Lcp.decipherTextFile(fileContent, license, key)
          .catch(error => {
            console.warn(`Can’t extract content of file at ${path}`, error);
            return '';
          });
      }
      return fileContent;
    });
}

function getLcpLicense(zip) {
  return getFile(zip, 'META-INF/license.lcpl')
    .then(licenseJson => {
      return JSON.parse(licenseJson);
    });
}

function getOpfContent(zip) {
  let basePath;

  return getFile(zip, 'META-INF/container.xml', BYTES_FORMAT)
  // finding .opf path in container.xml
    .then(parseXml, error => console.error('AAAAHHHH', error))
    .then(document => {
      const opfFilePath = getOpfFilePath(document);
      basePath = getBasePath(opfFilePath);
      return getFile(zip, opfFilePath);
    })
    .then(opfXml => {
      return hash({
        basePath: basePath,
        opf: parseXml(opfXml.trim())
      });
    });
}

function getBasePath(contentFilePath) {
  const result = contentFilePath.match(/^(\w*)\/\w*\.opf$/);
  if (result) {
    return result[1] + '/';
  }
  return '';
}

function getSpines(zip, keys = null, toc = null) {
  // if book is protected by CARE, we have to decipher its content
  let license = null;
  let userKey = null;

  return getLcpLicense(zip)
    .then(lcpLicense => {
      license = lcpLicense;
      return Lcp.getValidUserKey(keys, lcpLicense)
        .then(key => (userKey = key))
        .catch(console.warn);
    }, () => { /* book is not protected by CARE */
    })

    // finding spines in .opf
    .then(() => getOpfContent(zip))
    .then(({basePath, opf}) => {
      const validSpines = [];
      opf('spine > itemref').each((index, element) => {
        const spine = cheerio(element);
        const idref = spine.attr('idref');
        const item = opf(`manifest > item[id="${idref}"]`);
        if (isEmpty(item)) {
          return;
        }
        const href = item.attr('href');
        const validSpine = {
          idref,
          href,
          path: basePath + href
        };

        const spineProperties = spine.attr('properties');
        if (!isEmpty(spineProperties)) {
          validSpine.spread = spineProperties;
        }

        validSpines.push(validSpine);
      });

      return validSpines;
    })

    // compute each spine CFI
    .then(spines => {
      for (let spineIndex = 0; spineIndex < spines.length; spineIndex++) {
        spines[spineIndex].cfi = `/4/${2 + spineIndex * 2}`;
      }
      return spines;
    })

    // getting each file elements count
    .then(spines => {
      const promises = [];
      spines.forEach(spine => promises.push(analyzeSpine.call(this, zip, spine, license, userKey, toc)));
      return all(promises);
    });
}

function analyzeSpine(zip, spine, license, userKey, toc) {
  return getFileContent.call(this, zip, spine.path, license, userKey)
    .then(parseXml)
    .then(domContent => getSpineElementsCountInDom(domContent)
      .then(elementsCount => Object.assign(spine, elementsCount))
      .then(spine => enrichTocItems(toc, spine, domContent))
    )
    .catch(() => {
      console.warn(`Can’t analyze spine ${spine.path}`);
      return Object.assign(spine, EMPTY_ELEMENTS_COUNT);
    });
}

function getSpineElementsCountInDom(domContent) {
  return all([getCharacterCountInDom(domContent), getImageCountInDom(domContent), getVideoCountInDom(domContent)])
    .then(([characterCount, imageCount, videoCount]) => ({characterCount, imageCount, videoCount}))
    .then(estimateTotalCount)
    .catch(error => {
      console.warn('Content analyze failed', error);
      return EMPTY_ELEMENTS_COUNT;
    });
}

function getElementsCount(elements) {
  return all([getCharacterCount(elements), getImageCount(elements), getVideoCount(elements)])
    .then(([characterCount, imageCount, videoCount]) => ({characterCount, imageCount, videoCount}))
    .then(estimateTotalCount)
    .catch(error => {
      console.warn('Content analyze failed', error);
      return EMPTY_ELEMENTS_COUNT;
    });
}

function getCharacterCountInDom(domContent) {
  const elements = domContent('body *');
  return getCharacterCount(elements.toArray());
}

function getCharacterCount(elements) {
  return elements.reduce((total, el) => {
    const elementInnerContent = el.childNodes.filter(n => n.nodeType === TEXT_NODE).map(n => n.data).join('');
    return elementInnerContent.length + total;
  }, 0);
}

function getImageCountInDom(domContent) {
  const elements = domContent('img, svg image');
  return elements.length;
}

function getImageCount(elements) {
  const imageTagNames = ['img', 'image'];
  return elements.filter(el => imageTagNames.includes(el.tagName)).length;
}

function getVideoCountInDom(domContent) {
  const elements = domContent('video');
  return elements.length;
}

function getVideoCount(elements) {
  return elements.filter(el => el.tagName === 'video').length;
}

function enrichTocItems(items, spine, spineDomContent) {
  if (items) {
    const spineElements = spineDomContent('body *').toArray();

    findTocItemsInSpine(items, spine.href).map(item => {
      item.cfi = computeCfi(spine.cfi, spineDomContent, getHashFromHref(item.href));

      const itemElementId = spineElements.findIndex(el => el.id === getHashFromHref(item.href));
      if (itemElementId === -1) {
        item.positionInSpine = 0;
        return;
      }

      getElementsCount(spineElements.slice(0, itemElementId)).then(elementsCount => item.positionInSpine = elementsCount.totalCount / spine.totalCount);
    });
  }
  return spine;
}

function getHashFromHref(href) {
  const hrefSplit = href.split('#');
  return hrefSplit.length > 1 ? hrefSplit[1] : null;
}

function findTocItemsInSpine(items, href) {
  items = items || [];
  let matchingItems = items.filter(item => item.href.indexOf(href) === 0);
  items.forEach(item => {
    matchingItems = matchingItems.concat(findTocItemsInSpine(item.items, href))
  });
  return matchingItems;
}

function computeCfi() {
  return 'epubcfi';
}

function getOpfFilePath(document) {
  return document('rootfile').attr('full-path');
}

function getMetadata(zip) {
  return getOpfContent(zip)
    .then(({opf}) => {
      const fixedMetadata = {};
      const metadata = opf('metadata > *');

      metadata.each((index, entry) => {
        const data = extractMetadataEntry(entry);
        fixedMetadata[data.key] = data.value;
      });
      return fixedMetadata;
    });
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

function getToc(zip) {
  return getOpfContent(zip)
    .then(({basePath, opf}) => {
      // let tocItem = opf('item[media-type="application/x-dtbncx+xml"]'); // epub 2
      // if (isEmpty(tocItem)) {
      //   tocItem = opf('item[properties="nav"]'); // epub 3
      // }
      let tocItem = opf('item[properties="nav"]'); // epub 3
      if (isEmpty(tocItem)) {
        return null;
      }

      const tocFilename = tocItem.attr('href');
      return getFile(zip, basePath + tocFilename);
    })
    .then(parseXml)
    .then(parseToc)
    .catch(error => {
      console.warn('failed to parse toc file', error);
      return null;
    });
}

function getCoverData(zip) {
  return getCoverPath(zip)
    .then(coverFilePath => getFile(zip, coverFilePath, BYTES_FORMAT));
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

function getProtections(zip) {
  return getFile(zip, 'META-INF/encryption.xml', BYTES_FORMAT)
    .catch(() => {
    })
    .then(parseXml, error => {
      if (typeof error === 'string' && !error.match(/not found/)) {
        console.error(error);
      }
      return reject(error);
    })
    .then(encryptions => {
      return Array.from(encryptions.querySelectorAll('EncryptedData')).reduce((resources, data) => {
        let resourceProtection = PROTECTION_METHOD.UNKNOWN;

        const resourceUri = data.querySelector('CipherData > CipherReference').getAttribute('URI');
        const encryptionMethod = data.querySelector('EncryptionMethod');
        const retrievalMethod = data.querySelector('KeyInfo > RetrievalMethod');
        const keyResource = data.querySelector('KeyInfo > resource');

        if (retrievalMethod) {
          resourceProtection = retrievalMethod.getAttribute('URI');
        } else if (keyResource) {
          resourceProtection = keyResource.getAttribute('xmlns');
        } else {
          resourceProtection = encryptionMethod.getAttribute('Algorithm');
        }
        resources[resourceUri] = resourceProtection;

        return resources;
      }, {});
    })
    // Object.values is not implemented on all recent browsers
    .then(bookResources => Object.keys(bookResources).map(key => bookResources[key]).uniq())
    .catch(() => []);
}

function getDirPath(fileFullPath) {
  const dirPath = fileFullPath.split('/').slice(0, -1).join('/');
  return isEmpty(dirPath) ? '' : `${dirPath}/`;
}

function normalizePath(path) {
  const parts = path.split('/');

  return parts.reduce((path, part) => {
    if (part === '..') {
      return path.split('/').slice(0, -1).join('/');
    } else if (part === '.') {
      return path;
    }
    return `${path}${path.length === 0 ? '' : '/'}${part}`;
  });
}

function parseXml(data) {
  const xmlData = typeof data === 'string' ? data.trim() : bytesToString(data);
  return resolve(cheerio.load(xmlData, {xmlMode: true}));
}

function bytesToString(uint8array) {
  const charset = detectCharset(uint8array);

  if (typeof TextDecoder === 'undefined') {
    return String.fromCharCode.apply(null, uint8array);
  }

  const textDecoder = new TextDecoder(charset);
  return textDecoder.decode(uint8array);
}

function detectCharset(uint8array) {
  const utf16Test = uint8array.subarray(0, 2).join('-');
  if (utf16Test === UTF16LE_BOM_MARKER) {
    return UTF16LE;
  } else if (utf16Test === UTF16BE_BOM_MARKER) {
    return UTF16BE;
  }

  const utf32Test = uint8array.subarray(0, 4).join('-');
  if (utf32Test === UTF32LE_BOM_MARKER) {
    return UTF32LE;
  } else if (utf32Test === UTF32BE_BOM_MARKER) {
    return UTF32BE;
  }

  return UTF8;
}

function estimateTotalCount(elementsCounts) {
  elementsCounts.totalCount = elementsCounts.characterCount + 300 * elementsCounts.imageCount + 300 * elementsCounts.videoCount;
  return elementsCounts;
}

function computeTocItemsSizes(items, basePosition = 0, baseSize = 1) {
  if (isEmpty(items)) {
    return;
  }

  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    let sizeInSpine = baseSize;

    if (i + 1 < items.length) {
      const nextItem = items[i + 1];
      if (inSameSpine(item, nextItem)) {
        sizeInSpine = nextItem.positionInSpine - item.positionInSpine;
      }
    } else {
      sizeInSpine = baseSize + basePosition - item.positionInSpine;
    }

    if (sizeInSpine < 0) {
      console.warn('Can’t compute size of chapter in spine due to some weirdness in the ToC', item);
      sizeInSpine = 0;
    }

    computeTocItemsSizes(item.items, item.positionInSpine, sizeInSpine);

    item.percentageOfSpine = 100 * sizeInSpine;
  }
}

function inSameSpine(item1, item2) {
  return item1.href.split('#')[0] === item2.href.split('#')[0];
}

function generatePagination(tocItems, spines) {
  const totalCount = spines.reduce((total, spine) => total + spine.totalCount, 0);

  const elements = [];
  let spineIndex = 0, combinedSize = 0, maxLevel = 1;

  while (spineIndex < spines.length) {
    const spine = spines[spineIndex];
    const items = findTocItemsInSpine(tocItems, spine.href);
    maxLevel = items.reduce((max, item) => item.level > max ? item.level : max, maxLevel);

    let label;
    if (isEmpty(items)) {
      label = isEmpty(elements) ? spine.href.split('.')[0] : elements[spineIndex - 1].label;
    } else {
      label = items[0].label
    }

    const element = {
      items,
      label,
      percentageOfBook: 100 * spine.totalCount / totalCount,
      positionInBook: combinedSize
    };
    elements.push(element);

    combinedSize += element.percentageOfBook;
    spineIndex++;
  }

  return {
    totalCount,
    maxLevel,
    elements
  }
}

function testEpubFileValidity(epubData) {
  return !isAscmFile(epubData) && isZipFile(epubData);
}

function isAscmFile(epubData) {
  if (!TextDecoder) {
    console.warn('TextDecoder Object is not available');
    return false;
  }

  return new TextDecoder(UTF8).decode(epubData.slice(1, 17)) === ASCM_XML_ROOT_TAG;
}

function isZipFile(epubData) {
  if (!TextDecoder) {
    console.warn('TextDecoder Object is not available');
    return false;
  }

  const fileStartChunk = new TextDecoder('utf-8').decode(epubData.slice(0, 100));
  return fileStartChunk.indexOf(EPUB_FILE_MIME_TYPE) !== -1;
}
