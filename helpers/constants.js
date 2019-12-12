const CLASSIFICATION_TYPE_MAP = {
  blacklist: "Blacklisted",
  av_detected: "Detected by Anti-Malware",
  hacktool: "Hacking Tool",
  maltool: "Malicious tool",
  malware: "Malware",
  indifferent: "Neutral",
  no_type_found: "None found",
  ransomware: "Ransomware",
  sinkholed: "Sinkholed domain",
  suspicious: "Suspicious",
  unknown: "Unknown",
  unresolved: "Unresolved domain",
  unwanted: "Unwanted program",
  whitelist: "Whitelisted"
};

const FILE_CUSTOM_FIELDS = [
  "md5String",
  "sha1String",

  "productType",
  "productName",
  "extensionType",
  "fileDescription",
  "size",

  "companyName",
  "ownerMachine",

  "hasAutorun",
  "fileIsQuarantined",
  "hiddenFileExtensionEvidence",
  "hackingToolClassificationEvidence"
];

const QUERY_CONSTANTS = {
  ip: {
    queryType: "IpAddress",
    entityTypeSpecificCustomFields: [
      "countryNameOrNotExternalType",
      "city",
      "accessedByMalwaresOnly"
    ],
    searchOn: "elementDisplayName",
    customSuspicionFlags: ["accessedByMalwaresOnly"]
  },
  domain: {
    queryType: "DomainName",
    entityTypeSpecificCustomFields: [
      "isMaliciousDomainEvidence",
      "isInternalDomain",
      "isTorrentDomain",
      "isReverseLookup"
    ],
    searchOn: "elementDisplayName",
    customSuspicionFlags: [
      "isMaliciousDomainEvidence",
      "isInternalDomain",
      "isTorrentDomain",
      "isReverseLookup"
    ]
  },
  md5: {
    queryType: "File",
    entityTypeSpecificCustomFields: FILE_CUSTOM_FIELDS,
    searchOn: "md5String",
    customSuspicionFlags: [
      "hasAutorun",
      "fileIsQuarantined",
      "hiddenFileExtensionEvidence",
      "hackingToolClassificationEvidence"
    ]
  },
  sha1: {
    queryType: "File",
    entityTypeSpecificCustomFields: FILE_CUSTOM_FIELDS,
    searchOn: "sha1String",
    customSuspicionFlags: [
      "hasAutorun",
      "fileIsQuarantined",
      "hiddenFileExtensionEvidence",
      "hackingToolClassificationEvidence"
    ]
  },
  customFields: [
    "self",
    "relatedToMalop",
    "maliciousClassificationType",
    "elementDisplayName"
  ]
};

module.exports = {
  CLASSIFICATION_TYPE_MAP,
  QUERY_CONSTANTS
};
