const _ = require("lodash");

const getLookupResults = (results) =>
  _.chain(results)
    .filter(({ body }) => !_isMiss(body))
    .flatMap(({ entity: entityGroup, entityGroupType, body }) =>
      entityGroup
        .map((entity) => ({
          entity,
          data: _.chain(body)
            .filter(resultMatchesEntity(entityGroupType, entity))
            .map(formatResult)
            .thru(aggregrateResults(entityGroupType))
            .value()
        }))
        .filter(({ data }) => !_.isEmpty(data))
    )
    .value();

const _isMiss = (body) => !body || _.isEmpty(body);

const resultMatchesEntity = (entityGroupType, entity) => (result) =>
  ({
    ip: ({ elementDisplayName }) =>
      elementDisplayName.values[0].toLowerCase() === entity.value.toLowerCase(),
    domain: ({ elementDisplayName }) =>
      elementDisplayName.values[0].toLowerCase() === entity.value.toLowerCase(),
    md5: ({ md5String }) => md5String.values[0].toLowerCase() === entity.value.toLowerCase(),
    sha1: ({ sha1String }) => sha1String.values[0].toLowerCase() === entity.value.toLowerCase()
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
    machineNameOfFileLocation: ownerMachine.elementValues[0].name
  })
});

const aggregrateResults = (entityGroupType) =>
  ({
    ip: (results) => {
      const otherPossibleSuspicions = ["isMalicious", "hasMalops", "accessedByMalwaresOnly"];
      const suspicions = transformSuspicions(results, otherPossibleSuspicions);

      const maliciousClassificationTypes = createClassificationTypes(results);

      return {
        details: {
          test: JSON.stringify({
            name: results[0].elementDisplayName,
            country: results[0].countryNameOrNotExternalType,
            city: results[0].city,
            suspicionCount: suspicions.length,
            ...(suspicions.length && { suspicions }),
            ...(maliciousClassificationTypes.length && { maliciousClassificationTypes })
          })
        }
      };
    },
    domain: (results) => {
      const otherPossibleSuspicions = [
        "isMalicious",
        "hasMalops",
        "isMaliciousDomainEvidence",
        "isInternalDomain",
        "isTorrentDomain",
        "isReverseLookup"
      ];

      const suspicions = transformSuspicions(results, otherPossibleSuspicions);

      const maliciousClassificationTypes = createClassificationTypes(results);

      return {
        details: {
          test: JSON.stringify({
            name: results[0].elementDisplayName,
            suspicionCount: suspicions.length,
            ...(suspicions.length && { suspicions }),
            ...(maliciousClassificationTypes.length && { maliciousClassificationTypes })
          })
        }
      };
    },
    md5: (result) => ({ details: { test: JSON.stringify(result, null, 2) } }),
    sha1: (result) => ({ details: { test: JSON.stringify(result, null, 2) } })
  }[entityGroupType]);

const createClassificationTypes = (results) =>
  results.reduce(
    (agg, result) =>
      !agg.includes(result.maliciousClassificationType)
        ? [...agg, result.maliciousClassificationType]
        : agg,
    []
  );

const transformSuspicions = (results, otherPossibleSuspicionsKeys) => {
  /* 
  Input: results[i].suspicions = { blackListedFileSuspicion: 123422142342134 }
  Output: ["BlackListedFile"]
*/
  const normalSuspicionsFlags = _.chain(results)
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
  Output: ["IsMalicious"] for all flags that are true in result[i].key[i]
*/
  const otherPossibleSuspicionFlags = results.reduce(
    (agg, result) => [
      ...agg,
      ...otherPossibleSuspicionsKeys.reduce(
        (agg, suspicionKey) =>
          result[suspicionKey] && !agg.includes(_.upperFirst(suspicionKey))
            ? [...agg, _.upperFirst(suspicionKey)]
            : agg,
        []
      )
    ],
    []
  );

  return normalSuspicionsFlags.concat(otherPossibleSuspicionFlags);
};

module.exports = getLookupResults;
