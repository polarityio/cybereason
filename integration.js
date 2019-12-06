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

function doLookup(entities, options, cb) {
  let lookupResults = [];
  let tasks = [];

  Logger.debug(entities);

  let requestOptions = { method: "GET", uri: `${options.url}` };

  entities.forEach(entity => {
    tasks.push(function (done) {
      requestWithDefaults(requestOptions, function (error, res, body) {
        const statusCode = res && res.statusCode;
        if (error) {
          return done(error);
        }

        Logger.trace(requestOptions);
        Logger.trace(
          { body, statusCode: statusCode || "N/A" },
          "Result of Lookup"
        );

        done(null, {
          entity,
          body
        });
      });
    });
  });


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
}

const _isMiss = (body) => !body;

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
