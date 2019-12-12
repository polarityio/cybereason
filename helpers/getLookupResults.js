const _ = require("lodash");

const { QUERY_CONSTANTS, CLASSIFICATION_TYPE_MAP } = require("./constants");

const getLookupResults = (results) => {
  const getLookupResultDetailsForEntity = (body, entityGroupType, entity) =>
    _.chain(body)
      .filter(resultMatchesEntity(entityGroupType, entity))
      .map(formatResult)
      .thru(aggregrateResultsForEntity(entityGroupType))
      .value();
      
  return (
    _.chain(results)
      .filter(({ body }) => !_isMiss(body))
      .flatMap(({ entity: entityGroup, entityGroupType, body }) =>
        entityGroup
          .map((entity) => ({
            entity,
            data: getLookupResultDetailsForEntity(body, entityGroupType, entity)
          }))
          .filter(({ data }) => !_.isEmpty(data))
      )
      .value()
  );
};

const _isMiss = (body) => _.isEmpty(body);

const resultMatchesEntity = (entityGroupType, entity) => (result) =>
  ({
    ip: ({ elementDisplayName }) =>
      elementDisplayName.values[0].toLowerCase() === entity.value.toLowerCase(),
    domain: ({ elementDisplayName }) =>
      elementDisplayName.values[0].toLowerCase() === entity.value.toLowerCase(),
    md5: ({ md5String }) =>
      md5String.values[0].toLowerCase() === entity.value.toLowerCase(),
    sha1: ({ sha1String }) =>
      sha1String.values[0].toLowerCase() === entity.value.toLowerCase()
  }[entityGroupType](result.simpleValues));

const formatResult = ({
  simpleValues,
  elementValues: { self, ownerMachine },
  suspicions,
  isMalicious
}) => ({
  ..._.reduce(
    simpleValues,
    (agg, value, key) => ({ ...agg, [key]: value.values && value.values[0] }),
    {}
  ),
  isMalicious,
  hasMalops: self.elementValues[0].hasMalops,
  ...(!_.isEmpty(suspicions) && { suspicions }),
  ...(!_.isEmpty(ownerMachine) && {
    machineNameWhereFileIsLocated: ownerMachine.elementValues[0].name
  })
});

const aggregrateResultsForEntity = (entityGroupType) => (resultsForEntity) => {
  if (_.isEmpty(resultsForEntity)) return;

  const aggregateConsistentFields = (
    entityType, 
    createInconsistentFields = () => ({})
  ) => (resultsForEntity) => {
    const suspicions = transformSuspicions(
      resultsForEntity,
      QUERY_CONSTANTS[entityType].customSuspicionFlags.concat([
        "isMalicious",
        "hasMalops"
      ])
    );

    const maliciousClassificationTypes = createClassificationTypes(resultsForEntity);

    return {
      details: {
        ...createInconsistentFields(resultsForEntity),
        suspicionCount: suspicions.length,
        ...(suspicions.length && { suspicions }),
        ...(maliciousClassificationTypes.length && {
          maliciousClassificationTypes
        })
      }
    };
  };

  const aggregateFile = aggregateConsistentFields(entityGroupType, (resultsForEntity) => ({
    name: resultsForEntity[0].md5String,
    fileName: resultsForEntity[0].elementDisplayName,
    sha1Hash: resultsForEntity[0].sha1String,

    productType: resultsForEntity[0].productType,
    productName: resultsForEntity[0].productName,
    extensionType: resultsForEntity[0].extensionType,
    fileDescription: resultsForEntity[0].fileDescription,
    size: resultsForEntity[0].size,

    companyName: resultsForEntity[0].companyName,
    machineNamesWhereFileIsLocated: resultsForEntity.map(
      (result) => result.machineNameWhereFileIsLocated
    )
  }));

  return {
    ip: aggregateConsistentFields(entityGroupType, (resultsForEntity) => ({
      name: resultsForEntity[0].elementDisplayName,
      country: resultsForEntity[0].countryNameOrNotExternalType,
      city: resultsForEntity[0].city
    })),

    domain: aggregateConsistentFields(entityGroupType, (resultsForEntity) => ({
      name: resultsForEntity[0].elementDisplayName
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
  }, []);

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
        .upperFirst()
    )
    .values();

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
            !agg.includes(_.upperFirst(suspicionKey))
              ? [...agg, _.upperFirst(suspicionKey)]
              : agg,
          []
        )
      ),
    []
  );

  return normalSuspicionsFlags.concat(otherPossibleSuspicionFlags).sort();
};

module.exports = getLookupResults;
