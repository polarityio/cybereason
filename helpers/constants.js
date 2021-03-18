const CLASSIFICATION_TYPE_MAP = {
  blacklist: 'Blacklisted',
  av_detected: 'Detected by Anti-Malware',
  hacktool: 'Hacking Tool',
  maltool: 'Malicious tool',
  malware: 'Malware',
  indifferent: 'Neutral',
  no_type_found: 'None found',
  ransomware: 'Ransomware',
  sinkholed: 'Sinkholed domain',
  suspicious: 'Suspicious',
  unknown: 'Unknown',
  unresolved: 'Unresolved domain',
  unwanted: 'Unwanted program',
  whitelist: 'Whitelisted'
};

const EXTENSION_TYPE_MAP = {
  APPLICATION: 'Application',
  APPLICATION_DATA: 'Application Data',
  ARCHIVE: 'Archive',
  DOCUMENT_AUDIO: 'Audio File',
  CERTIFICATE: 'Certificate',
  APPLICATION_CONFIG: 'Compressed Archive',
  ARCHIVE_COMPRESSED: 'Configuration File',
  DATABASE: 'Database',
  DOCUMENT_DEVELOPER: 'Developer File',
  ARCHIVE_DISKIMAGE: 'Disk Image',
  DOCUMENT: 'Document',
  EXECUTABLE: 'Executable',
  DOCUMENT_IMAGE: 'Image',
  DOCUMENT_MAIL: 'Mail File',
  EXECUTABLE_INSTALLER: 'Installer',
  NONE: 'None',
  DOCUMENT_PERSONALINFORMATION: 'Personal Data',
  EXECUTABLE_PLUGIN: 'Plugin',
  EXECUTABLE_SCRIPT: 'Script File',
  SYSTEM: 'System File',
  DOCUMENT_TEXT: 'Text File',
  DOCUMENT_VIDEO: 'Video File',
  DOCUMENT_WEB: 'Web Document',
  EXECUTABLE_WEB: 'Web Executable',
  EXECUTABLE_WINDOWS: 'Windows System File',
  SYSTEM_WINDOWS: 'Windows System File'
};

const PRODUCT_TYPE_MAP = {
  ADOBE: 'Adobe',
  'ANTI-VIRUS': 'Antivirus',
  BROWSER: 'Browser',
  EXPLORER: 'Explorer',
  MAIL: 'Lsass',
  LSASS: 'Mail',
  MS_OFFICE: 'Microsoft Office',
  OS_PROCESS: 'OS process',
  P2P: 'Peer to Peer',
  REMOTE_DESKTOP_CONTROL: 'Remote Desktop',
  RUNAS: 'RunAs',
  RUNDLL: 'RunDll',
  SVCHOST: 'SVC Host',
  SCHEDULED_TASK: 'Scheduled task',
  SECURITY_TOOL: 'Security tool',
  SHARING: 'Sharing',
  SHELL: 'Shell',
  TOR: 'Tor',
  UNRECOGNIZED: 'Unrecognized',
  VPN: 'VPN',
  VIRTUALIZATION: 'Virtualization',
  WININIT: 'Wininit',
  WSMPROVHOST: 'WsmProvHost'
};

const FILE_CUSTOM_FIELDS = [
  'md5String',
  'sha1String',

  'productType',
  'productName',
  'extensionType',
  'fileDescription',
  'size',

  'companyName',
  'ownerMachine',

  'hasAutorun',
  'fileIsQuarantined',
  'hiddenFileExtensionEvidence',
  'hackingToolClassificationEvidence'
];

const QUERY_CONSTANTS = {
  ip: {
    queryType: 'IpAddress',
    entityTypeSpecificCustomFields: ['countryNameOrNotExternalType', 'city', 'accessedByMalwaresOnly'],
    searchOn: 'elementDisplayName',
    customSuspicionFlags: ['accessedByMalwaresOnly']
  },
  domain: {
    queryType: 'DomainName',
    entityTypeSpecificCustomFields: [
      'isMaliciousDomainEvidence',
      'isInternalDomain',
      'isTorrentDomain',
      'isReverseLookup'
    ],
    searchOn: 'elementDisplayName',
    customSuspicionFlags: ['isMaliciousDomainEvidence', 'isInternalDomain', 'isTorrentDomain', 'isReverseLookup']
  },
  md5: {
    queryType: 'File',
    entityTypeSpecificCustomFields: FILE_CUSTOM_FIELDS,
    searchOn: 'md5String',
    customSuspicionFlags: [
      'hasAutorun',
      'fileIsQuarantined',
      'hiddenFileExtensionEvidence',
      'hackingToolClassificationEvidence'
    ]
  },
  sha1: {
    queryType: 'File',
    entityTypeSpecificCustomFields: FILE_CUSTOM_FIELDS,
    searchOn: 'sha1String',
    customSuspicionFlags: [
      'hasAutorun',
      'fileIsQuarantined',
      'hiddenFileExtensionEvidence',
      'hackingToolClassificationEvidence'
    ]
  },
  customFields: ['self', 'relatedToMalop', 'maliciousClassificationType', 'elementDisplayName']
};

module.exports = {
  CLASSIFICATION_TYPE_MAP,
  EXTENSION_TYPE_MAP,
  PRODUCT_TYPE_MAP,
  QUERY_CONSTANTS
};
