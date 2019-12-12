const { QUERY_CONSTANTS } = require("./constants");

const generateRequestBody = (entityGroup, entityGroupType) => {
  const { 
    queryType, 
    searchOn, 
    entityTypeSpecificCustomFields 
  } = QUERY_CONSTANTS[entityGroupType];

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
