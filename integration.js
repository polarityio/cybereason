"use strict";

const request = require("request");
const _ = require("lodash");
const config = require("./config/config");
const async = require("async");
const fs = require("fs");

let Logger;
let requestWithDefaults;

const MAX_PARALLEL_LOOKUPS = 10;

const NodeCache = require("node-cache");
const tokenCache = new NodeCache({
  stdTTL: 1000 * 1000
});

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
    }, (err, resp, body) => {
      if (err) {
        callback(err);
        return;
      }

      Logger.trace({ resp }, "Result of token lookup");

      if (resp.statusCode !== 200 && resp.statusCode !== 302) {
        callback({ err: new Error("status code was not 200"), body });
        return;
      }

      let cookie = resp.headers['set-cookie'][0].split(";")[0];
      if (typeof cookie === undefined) {
        callback({ err: new Error("Cookie Not Avilable"), body });
        return;
      }

      tokenCache.set(cacheKey, { cookie });

      Logger.trace({ tokenCache }, "Checking TokenCache");

      callback(null, { cookie });
    }
  );
}

function generateRequestBody(entity) {
  return {
    queryPath: [
        {
            requestedType: "DomainName",
            result: true,
            filters: [
                {
                    facetName: "elementDisplayName",
                    values: [
                        "r2.sn-vgqsknes.gvt1.com"
                    ],
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
    customFields: [
        "self",
        "elementDisplayName",
        "name",
        "topLevelDomain",
        "secondLevelDomain",
        "maliciousClassificationType",
        "relatedToMalop",
        "isTorrentDomain",
        "isInternalDomain",
        "isInternalSecondLevelDomain",
        "everResolvedDomain",
        "everResolvedSecondLevelDomain",
        "isReverseLookup"
    ]
}
}

function doLookup(entities, options, cb) {
  Logger.debug(entities, "Entities");

  getAuthToken(options, (err, token) => {
    if (err) {
      Logger.error("Get token errored", err);
      return;
    }

    Logger.trace({ token }, "Token in doLookup");


    const tasks = entities.map(entity => (done) =>
      requestWithDefaults({
        method: "post",
        uri: `${options.url}/rest/visualsearch/query/simple`,
        headers: {
          Cookie: token.cookie,
          "Content-Type": "application/json"
        },
        body: generateRequestBody(entity),
        json: true
      }, (error, res, body) => {
        if (error) {
          return done(error);
        }
        const statusCode = res && res.statusCode;


        Logger.trace(
          { body, statusCode: statusCode || "N/A" },
          "Result of Lookup"
        );

        done(null, {
          entity,
          body
        });
      })
    );

    let lookupResults = [];
    async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
      if (err) {
        Logger.error({ err }, "Error");
        cb(err);
        return;
      }

      results.forEach(({ body, entity }) => {
        if (body === null || _isMiss(body) || _.isEmpty(body)) {
          lookupResults.push({
            entity,
            data: {
              details: { test: "This is a test placeholder" }
            }
          });
        } else {
          lookupResults.push({
            entity,
            data: {
              details: { test: "This is a test placeholder" }
            }
          });
        }
      });

      Logger.debug({ lookupResults }, "Results");
      cb(null, lookupResults);
    });
  })
}

const _isMiss = (body) => !body;

function startup(logger) {
  let defaults = {};
  Logger = logger;

  const { cert, key, ca, passphrase, proxy, rejectUnauthorized } = config.request;

  if (typeof cert === "string" && cert.length > 0) {
    defaults.cert = fs.readFileSync(cert);
  }

  if (typeof key === "string" && key.length > 0) {
    defaults.key = fs.readFileSync(key);
  }

  if (typeof ca === "string" && ca.length > 0) {
    defaults.ca = fs.readFileSync(ca);
  }

  if (typeof passphrase === "string" && passphrase.length > 0) {
    defaults.passphrase = passphrase;
  }

  if (typeof proxy === "string" && proxy.length > 0) {
    defaults.proxy = proxy;
  }

  if (typeof rejectUnauthorized === "boolean") {
    defaults.rejectUnauthorized = rejectUnauthorized;
  }

  requestWithDefaults = request.defaults(defaults);
}

function validateStringOption(errors, options, optionName, errMessage) {
  if (
    typeof options[optionName].value !== "string" ||
    (typeof options[optionName].value === "string" &&
      options[optionName].value.length === 0)
  ) {
    errors.push({
      key: optionName,
      message: errMessage
    });
  }
}

function validateOptions(options, callback) {
  let errors = [];

  validateStringOption(
    errors,
    options,
    "url",
    "You must provide a valid API URL"
  );
  validateStringOption(
    errors,
    options,
    "username",
    "You must provide a valid Username"
  );
  validateStringOption(
    errors,
    options,
    "password",
    "You must provide a valid Password"
  );
  callback(null, errors);
}

module.exports = {
  doLookup,
  startup,
  validateOptions
};
