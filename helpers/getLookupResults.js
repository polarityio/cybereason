const _ = require("lodash");

const { 
  QUERY_CONSTANTS, 
  CLASSIFICATION_TYPE_MAP, 
  EXTENSION_TYPE_MAP,
  PRODUCT_TYPE_MAP
} = require("./constants");

const getLookupResults = (results, { url, onlyShowEntitiesWithSuspicions }) =>
  _.chain(results)
    .filter(({ body }) => !_isMiss(body))
    .flatMap(({ entity: entityGroup, entityGroupType, body }) =>
      entityGroup
        .map((entity) => ({
          entity,
          data: getLookupResultDetailsForEntity(body, entityGroupType, entity, url)
        }))
        .filter(({ data }) => 
          !_.isEmpty(data) || 
          (onlyShowEntitiesWithSuspicions && data.details.suspicionCount)
        )
    )
    .value()

const _isMiss = (body) => _.isEmpty(body);

const getLookupResultDetailsForEntity = (body, entityGroupType, entity, url) =>
  _.chain(body)
    .filter(resultMatchesEntity(entityGroupType, entity))
    .map(formatResult)
    .thru(aggregrateResultsForEntity(entityGroupType, url))
    .value();

const resultMatchesEntity = (entityGroupType, entity) => (result) => {
  const compareEntityToResult = (key) => (simpleValue) => 
    simpleValue[key][0].toLowerCase()=== entity.value.toLowerCase();

  return ({
    ip: compareEntityToResult("elementDisplayName"),
    domain: compareEntityToResult("elementDisplayName"),
    md5: compareEntityToResult("md5String"),
    sha1: compareEntityToResult("sha1String")
  }[entityGroupType](result.simpleValues));
};

const formatResult = ({
  simpleValues,
  elementValues: { self, ownerMachine },
  suspicions,
  isMalicious,
  guid
}) => ({
  ..._.reduce(
    simpleValues,
    (agg, value, key) => ({ ...agg, [key]: value.values && value.values[0] }),
    {}
  ),
  guid,
  isMalicious,
  hasMalops: self.elementValues[0].hasMalops,
  ...(!_.isEmpty(suspicions) && { suspicions }),
  ...(!_.isEmpty(ownerMachine) && {
    machineNameWhereFileIsLocated: ownerMachine.elementValues[0].name
  })
});

const aggregrateResultsForEntity = (entityGroupType, url) => (resultsForEntity) => {
  if (_.isEmpty(resultsForEntity)) return;

  const aggregateConsistentFields = (
    entityType, 
    url,
    createInconsistentFields = () => ({})
  ) => (resultsForEntity) => {
    const { customSuspicionFlags, queryType } = QUERY_CONSTANTS[entityType];

    const suspicions = transformSuspicions(
      resultsForEntity,
      customSuspicionFlags.concat([
        "isMalicious",
        "hasMalops"
      ])
    );
    
    const maliciousClassificationTypes = createClassificationTypes(resultsForEntity);

    return {
      details: {
        suspicionCount: suspicions.length,
        expandedlink: 
          `${url}/#/element?rootType=${queryType}` +
          `&viewedGuids=${resultsForEntity.map(({guid}) => guid).join(",")}`,
        ...(suspicions.length && { suspicions }),
        ...(maliciousClassificationTypes.length && { maliciousClassificationTypes }),
        ...createInconsistentFields(resultsForEntity)
      }
    };
  };

  const aggregateFile = aggregateConsistentFields(entityGroupType, url, (resultsForEntity) => ({
    entityType: entityGroupType.toUpperCase(),
    fileName: resultsForEntity[0].elementDisplayName,
    md5Hash: resultsForEntity[0].md5String,
    sha1Hash: resultsForEntity[0].sha1String,

    productType: PRODUCT_TYPE_MAP[resultsForEntity[0].productType],
    productName: resultsForEntity[0].productName,
    extensionType: EXTENSION_TYPE_MAP[resultsForEntity[0].extensionType],
    fileDescription: resultsForEntity[0].fileDescription,
    size: resultsForEntity[0].size,

    companyName: resultsForEntity[0].companyName,
    machineNamesWhereFileIsLocated: _.chain(resultsForEntity)
      .map((result) => result.machineNameWhereFileIsLocated)
      .uniq()
      .value()
  }));

  return {
    ip: aggregateConsistentFields(entityGroupType, url, (resultsForEntity) => ({
      entityType: "IPv4",
      country: resultsForEntity[0].countryNameOrNotExternalType,
      city: resultsForEntity[0].city
    })),
    domain: aggregateConsistentFields(entityGroupType, url, () => ({
      entityType: "Domain"
    })),
    md5: aggregateFile,
    sha1: aggregateFile
  }[entityGroupType](resultsForEntity);
};

const createClassificationTypes = (resultsForEntity) =>
  resultsForEntity.reduce((agg, { maliciousClassificationType }) => {
    if (_.isEmpty(maliciousClassificationType)) return agg;

    const classType = CLASSIFICATION_TYPE_MAP[maliciousClassificationType];

    return !agg.includes(classType) ? [...agg, classType] : agg;
  }, []).join(", ");

const transformSuspicions = (resultsForEntity, otherPossibleSuspicionsKeys) => {
  /* 
    Input: resultsForEntity[i].suspicions = { blackListedFileSuspicion: 123422142342134 }
    Output: ["BlackListedFile"]
  */
  const normalSuspicionsFlags = _.chain(resultsForEntity)
    .filter(({ suspicions }) => suspicions)
    .flatMap((result) => _.keys(result.suspicions))
    .uniq()
    .map((unformattedSuspicions) =>
      _.chain(unformattedSuspicions)
        .replace("Suspicion", "")
        .startCase()
        .value()
    )
    .value();

  /* 
    Input: otherPossibleSuspicionsKeys = ["isMalicious", "hasMalops"]
    Output: ["IsMalicious"] only if that flag is true on at least one result
  */
  const otherPossibleSuspicionFlags = resultsForEntity.reduce(
    (agg, result) =>
      agg.concat(otherPossibleSuspicionsKeys.reduce(
          (agg, suspicionKey) =>
            result[suspicionKey] &&
            result[suspicionKey] !== "false" &&
            !agg.includes(_.startCase(suspicionKey))
              ? [...agg, _.startCase(suspicionKey)]
              : agg,
          []
        )
      ),
    []
  );

  return [...normalSuspicionsFlags, ...otherPossibleSuspicionFlags].sort();
};

module.exports = getLookupResults;
