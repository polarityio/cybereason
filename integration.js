"use strict";

const request = require("request");
const _ = require("lodash");
const async = require("async");
const NodeCache = require("node-cache");

const { validateOptions, getRequestWithDefaults } = require("./helpers/validateAndStartup");

const generateRequestBody = require("./helpers/generateRequestBody");
const handleRequestStatusCode = require("./helpers/handleRequestStatusCode");
const getLookupResults = require("./helpers/getLookupResults");

let Logger;
let requestWithDefaults;
const MAX_PARALLEL_LOOKUPS = 10;

const tokenCache = new NodeCache({
  stdTTL: 8 * 60 * 60 - 1200 //Token lasts 8 hours
});

function startup(logger) {
  Logger = logger;
  requestWithDefaults = getRequestWithDefaults();
}

function getAuthToken({ url: cyberReasonUrl, username, password }, callback) {
  const cacheKey = `${username}${password}`;

  const cachedToken = tokenCache.get(cacheKey);
  if (cachedToken) return callback(null, cachedToken);

  request(
    {
      method: "POST",
      uri: `${cyberReasonUrl}/login.html`,
      qs: {
        username,
        password
      },
      headers: { "Content-Type": "application/x-www-form-urlencoded" }
    },
    (err, resp, body) => {
      if (err) {
        callback(err);
        return;
      }

      Logger.trace({ resp }, "Result of token lookup");

      if (resp.statusCode !== 200 && resp.statusCode !== 302) {
        callback({ err: new Error("status code was not 200"), body });
        return;
      }

      const cookie =
        resp.headers["set-cookie"] &&
        resp.headers["set-cookie"][0] &&
        typeof resp.headers["set-cookie"][0] === "string" &&
        resp.headers["set-cookie"][0].split(";")[0];

      if (!cookie) return callback({ err: new Error("Cookie Not Avilable"), body });

      tokenCache.set(cacheKey, { cookie });

      Logger.trace({ tokenCache }, "Checking TokenCache");

      callback(null, { cookie });
    }
  );
}

const formatQueryResponse = (entityGroup, entityGroupType, done) => (requestError, res, body) => {
  if (requestError) return done(requestError);

  const statusCode = res && res.statusCode;

  Logger.trace({ body, statusCode: statusCode || "N/A" }, "Result of Lookup");

  const [statusError, result] = handleRequestStatusCode(entityGroup, statusCode, body);
  if (statusError) return done(statusError);

  if (_.isEmpty(result.body.data.resultIdToElementDataMap)) return done(null, { ...result, body: null });

  done(null, {
    ...result,
    entityGroupType,
    body: _.map(result.body.data.resultIdToElementDataMap, (value) => value)
  });
};

const createRequestQueue = (entities, options, token) =>
  _.chain(entities)
    //TODO: Ask if domains also should be search in files
    .groupBy(({ isIP, isDomain, isMD5, isSHA1 }) =>
      isIP ? "ip" : isDomain ? "domain" : isMD5 ? "md5" : isSHA1 ? "sha1" : "unknown"
    )
    .map((entityGroup, entityGroupType) => (done) =>
      entityGroupType !== "unknown" &&
      requestWithDefaults(
        {
          method: "post",
          uri: `${options.url}/rest/visualsearch/query/simple`,
          headers: {
            Cookie: token.cookie,
            "Content-Type": "application/json"
          },
          body: generateRequestBody(entityGroup, entityGroupType),
          json: true
        },
        formatQueryResponse(entityGroup, entityGroupType, done)
      )
    )
    .value();



function doLookup(entities, options, cb) {
  Logger.trace({ entities }, "Entities");

  getAuthToken(options, (err, token) => {
    if (err) {
      Logger.error("Get token errored", err);
      return;
    }

    Logger.trace({ token }, "Token in doLookup");

    const requestQueue = createRequestQueue(entities, options, token);

    async.parallelLimit(requestQueue, MAX_PARALLEL_LOOKUPS, (err, results) => {
      if (err) {
        Logger.error({ err }, "Error");
        return cb(err);
      }

      const lookupResults = getLookupResults(results);

      Logger.trace({ lookupResults }, "Results");
      cb(null, lookupResults);
    });
  });
}


module.exports = {
  doLookup,
  startup,
  validateOptions
};
