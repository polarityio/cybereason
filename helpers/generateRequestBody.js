const FILE_CUSTOM_FIELDS = [
  "name",
  "md5String",
  "sha1String",

  "productType",
  "productName",
  "extensionType",
  "fileDescription",
  "size",

  "hasAutorun",
  "fileIsQuarantined",
  "hiddenFileExtensionEvidence",
  "hackingToolClassificationEvidence",
  "whitelistClassificationEvidence",
  "blackListedFileSuspicion",

  "companyName",
  "ownerMachine"
];

const QUERY_CONSTANTS = {
  ip: {
    queryType: "IpAddress",
    entityTypeSpecificCustomFields: [
      "countryNameOrNotExternalType",
      "city",
      "accessedByMalwaresOnly"
    ],
    searchOn: "elementDisplayName"
  },
  domain: {
    queryType: "DomainName",
    entityTypeSpecificCustomFields: [
      "isMaliciousDomainEvidence",
      "isInternalDomain",
      "isTorrentDomain",
      "isReverseLookup"
    ],
    searchOn: "elementDisplayName"
  },
  md5: {
    queryType: "File",
    entityTypeSpecificCustomFields: FILE_CUSTOM_FIELDS,
    searchOn: "md5String"
  },
  sha1: {
    queryType: "File",
    entityTypeSpecificCustomFields: FILE_CUSTOM_FIELDS,
    searchOn: "sha1String"
  },
  customFields: [
    "self",
    "relatedToMalop",
    "maliciousClassificationType",
    "elementDisplayName"
  ]
};

const generateRequestBody = (entityGroup, entityGroupType) => {
  const { queryType, searchOn, entityTypeSpecificCustomFields } = QUERY_CONSTANTS[entityGroupType];

  return {
    queryPath: [
      {
        requestedType: queryType,
        filters: [
          {
            facetName: searchOn,
            values: entityGroup.map((entity) => entity.value),
            filterType: "ContainsIgnoreCase"
          }
        ],
        connectionFeature: {
          elementInstanceType: "Connection",
          featureName: "remoteAddress"
        },
        isReversed: true,
        isResult: true
      }
    ],
    totalResultLimit: 1000,
    perGroupLimit: 1000,
    perFeatureLimit: 100,
    templateContext: "DETAILS",
    customFields: QUERY_CONSTANTS.customFields.concat(entityTypeSpecificCustomFields)
  };
};

module.exports = generateRequestBody;
