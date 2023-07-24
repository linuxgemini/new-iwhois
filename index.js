/**
 * New Generation Interactive WHOIS
 * @author linuxgemini
 * @license
 * Copyright 2020 İlteriş Yağıztegin Eroğlu (linuxgemini)
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

"use strict";

const ipaddress = require("ip-address");
const WHOIS = require("./libs/whois");
const whois = new WHOIS();

const redis = require("redis");
const { RateLimiterRedis } = require("rate-limiter-flexible");

const express = require("express");

let config, ipAddresses, redisRatelimitClient, redisCacheClient, rateLimitPoints, rateLimitDuration, rateLimiter, rateLimiterMiddleware, app;

/**
 * @param {Error} err
 */
const exitWithError = (err) => {
    console.error("\n\nAn error occured!\n");
    if (err.stack) console.error(`\nStacktrace:\n${err.stack}\n`);
    return setTimeout(() => {
        process.exit(1);
    }, 1000);
};

const strStrip = (str) => str.replace(/^(\s+)|(\s+)$/g, "");

/**
 * @param {string} str
 */
const getIPIdentifierHex = (str) => {
    if (ipaddress.Address4.isValid(str)) {
        return (new ipaddress.Address4(`${str}/24`)).startAddress().toHex().toUpperCase();
    } else if (ipaddress.Address6.isValid(str)) {
        return Buffer.from((new ipaddress.Address6(`${str}/64`)).startAddress().toByteArray()).toString("hex").toUpperCase();
    } else {
        return;
    }
};

const constructIP = (reqip, reqips) => {
    let xfwip = (reqips && Array.isArray(reqips) ? reqips[0] : reqip);
    let host = (xfwip && xfwip !== reqip ? xfwip : reqip).replace(/^(::ffff:)/, "");
    let hostLog = (xfwip && xfwip !== reqip ? (xfwip + "," + reqip) : reqip).replace(/^(::ffff:)/, "");

    return {
        host,
        hostLog
    };
};

/**
 * @param {express.Request} req
 * @param {express.Response} res
 * @param {express.NextFunction} next
 * @param {boolean} skipNext
 */
const handleLog = (req, res, next, skipNext = false) => {
    let { hostLog } = constructIP(req.ip, req.ips);
    let isRatelimited = (res.statusCode === 429);

    console.log(`${Math.round(Date.now() / 1000)} ${hostLog} ${req.method} ${res.statusCode} ${req.hostname} ${req.originalUrl} '{rateLimited:${isRatelimited},protocol:"${req.protocol}"}'`);
    if (!isRatelimited && !skipNext) next();
};

/**
 * @param {express.Request} req
 * @param {express.Response} res
 * @param {express.NextFunction} next
 */
const handleRobots = (req, res, next) => {
    res.set("Content-Type", "text/plain; charset=utf-8");
    res.status(200).send(`User-agent: *
Allow: /$
Disallow: /`);
    handleLog(req, res, next, true);
};

/**
 * @param {express.Request} req
 * @param {express.Response} res
 * @param {express.NextFunction} next
 */
const handleRoot = (req, res, next) => {
    res.set("Content-Type", "text/html; charset=utf-8");
    res.status(200).send(`<!DOCTYPE html>
<html>
    <head>
        <title>linuxgemini's simple whois server</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="apple-mobile-web-app-capable" content="yes">
        <noscript>
            <meta http-equiv="refresh" content="0; URL=noscript.txt" />
        </noscript>
        <script>
            function setPlaceholder(value) {
                var whval = document.getElementById('whoisval');
                switch (value) {
                    case "w":
                        whval.placeholder = "google.com";
                        break;
                    case "ww":
                        whval.placeholder = "google.com";
                        break;
                    case "ripe":
                        whval.placeholder = "ORG-TCA23-RIPE";
                        break;
                    case "arin":
                        whval.placeholder = "a 174";
                        break;
                    case "afrinic":
                        whval.placeholder = "AS33762";
                        break;
                    case "apnic":
                        whval.placeholder = "AS131073";
                        break;
                    case "lacnic":
                        whval.placeholder = "AS8167";
                        break;
                    case "radb":
                        whval.placeholder = "1.1.1.0/24";
                        break;
                    default:
                        whval.placeholder = "";
                        break;
                }
            }
            window.addEventListener('load', function (event) {
                document.getElementById('whoisval').placeholder = "google.com";
            });
        </script>
    </head>
    <body>
        <h2>simple whois server</h2>
        </br>
        <p>
            hello!
            </br>example route for standard recursive whois: <a href="w/google.com">/w/google.com</a>
            </br>example route for verbose recursive whois: <a href="ww/google.com">/ww/google.com</a>
            </br>example route for whois for RIPE (-B flag is already added): <a href="ripe/ORG-TCA23-RIPE">/ripe/ORG-TCA23-RIPE</a>
            </br>example route for whois for ARIN: <a href="arin/a%20174">/arin/a 174</a>
            </br>example route for whois for AFRINIC (-B flag is already added): <a href="afrinic/AS33762">/afrinic/AS33762</a>
            </br>example route for whois for APNIC: <a href="apnic/AS131073">/apnic/AS131073</a>
            </br>example route for whois for LACNIC: <a href="lacnic/AS8167">/lacnic/AS8167</a>
            </br>example route for whois for RADb: <a href="radb/1.1.1.0/24">/radb/1.1.1.0/24</a>
            <noscript>
                </br>
                </br><b>Sorry, you have JavaScript disabled!</b>
                </br><b>Use the above examples as detailed usage.</b>
            </noscript>
        </p>
        </br>
        <label for="method">WHOIS Host:</label>
        <select id="method" onchange="setPlaceholder(this.value)">
            <option value="w" selected>recursive</option>
            <option value="ww">recursive-verbose</option>
            <option value="ripe">ripe</option>
            <option value="arin">arin</option>
            <option value="afrinic">afrinic</option>
            <option value="apnic">apnic</option>
            <option value="lacnic">lacnic</option>
            <option value="radb">radb</option>
        </select>
        </br>
        </br>
        <label for="whoisval">Target:</label>
        <input type="text" id="whoisval" value="">
        <input type="submit" id="postit" onclick="if (document.getElementById('whoisval').value !== '') window.location.href=document.getElementById('method').value+'/'+document.getElementById('whoisval').value">
        </br>
        </br>
        <p>Powered by <a href="https://github.com/linuxgemini/new-iwhois">new-iwhois</a> by <a href="https://linuxgemini.space">linuxgemini</a></p>
        <script>
            var node = document.getElementById("whoisval");
            node.addEventListener("keyup", function(event) {
                if (event.key === "Enter") {
                    if (document.getElementById("whoisval").value !== "") window.location.href = document.getElementById("method").value + "/" + document.getElementById("whoisval").value;
                }
            });
        </script>
    </body>
</html>`);
    handleLog(req, res, next, true);
};

/**
 * @param {string} query
 */
const fetchFromCache = (query) => {
    return new Promise((resolve, reject) => {
        if (!redisCacheClient) return reject(new Error("Redis Cache Client is not set!"));

        redisCacheClient.get(query, (err, data) => {
            if (err) return reject(err);
            if (data !== null) return resolve(data);
            return resolve("");
        });
    });
};

/**
 * @param {string} query
 * @param {string} value
 */
const setCache = (query, value) => {
    if (!redisCacheClient) throw new Error("Redis Cache Client is not set!");

    return redisCacheClient.setex(query, 1800, value);
};

/**
 * @param {express.Request} req
 * @param {express.Response} res
 * @param {express.NextFunction} next
 * @param {string} queryType
 */
const handleQuery = async (req, res, next, queryType) => {
    /** @type {string} */
    let result;
    /** @type {Error} */
    let error;
    /** @type {string[]} */
    let whoisValues = strStrip(req.params["whoisValue"]).split(" ");
    let queryValue = whoisValues.slice(-1).join(""); // why not `(-1)[0]`? well, if thats undefined we might get poof
    let queryOptions = whoisValues.slice(0, -1).join(" ");

    if (queryOptions.length > 0) queryValue = `${queryOptions} ${queryValue}`;

    try {
        result = await fetchFromCache(`${queryType}/${queryValue}`);
    } catch (e) {
        result = "";
    }

    if (!result || result === "") {
        try {
            switch (queryType) {
                case "recursive":
                    result = await whois.queryRecursive(queryValue);
                    break;
                case "recursive-verbose":
                    result = await whois.queryRecursiveVerbose(queryValue, 0, null, null, null, 43, null, false);
                    break;
                case "ripe":
                    result = await whois.queryRIPE(queryValue);
                    break;
                case "arin":
                    result = await whois.queryARIN(queryValue);
                    break;
                case "afrinic":
                    result = await whois.queryAFRINIC(queryValue);
                    break;
                case "apnic":
                    result = await whois.queryAPNIC(queryValue);
                    break;
                case "lacnic":
                    result = await whois.queryLACNIC(queryValue);
                    break;
                case "radb":
                    result = await whois.queryRADb(queryValue);
                    break;
                default:
                    throw new Error("Scripting Error");
            }
        } catch (err) {
            error = err;
            result = err.message;
        }
    }

    let isConnectionFailed = result.match(/connection (timeout|closed)/gi);
    let hasLibraryComment = result.includes("%#%");

    if (!hasLibraryComment && !isConnectionFailed && error) {
        throw error;
    }

    for (const addr of ipAddresses) {
        let reg = new RegExp(addr.replace(/\./g, "\\."), "g");
        result = result.replace(reg, "REDACTED");
    }

    // curl moment
    result = `${result}\n`;

    if (!isConnectionFailed) setCache(`${queryType}/${queryValue}`, result);

    res.set("Content-Type", "text/plain; charset=utf-8");
    res.status(200).send(result);

    handleLog(req, res, next, true);
};

const main = async () => {
    try {
        config = require("./config.json");
    } catch (e) {
        return exitWithError(new Error("Config file not found! Please check config.json.example"));
    }

    ipAddresses = [];

    for (const interfaceArray of Object.values(require("os").networkInterfaces())) {
        for (const ipObj of interfaceArray) {
            let addr = ipObj.address;

            if (ipObj.internal) continue;
            if (ipObj.family === "IPv4") {
                if (addr.startsWith("10.") || addr.startsWith("192.168.")) continue;
                if (addr.match(/^172\.(1[6-9]|2[0-9]|3[01])/)) continue;
                if (addr.match(/^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])/)) continue;
            } else {
                if (addr.startsWith("::ffff")) continue;
                if (addr.startsWith("fc") || addr.startsWith("fd") || addr.startsWith("fe") || addr.startsWith("ff")) continue;
                if (addr.startsWith("64:ff9b::") || addr.startsWith("100::") || addr.startsWith("2001:db8::")) continue;
            }

            ipAddresses.push(addr);
        }
    }

    redisRatelimitClient = redis.createClient(config.redisConfig);
    redisCacheClient = redis.createClient({
        host: config.redisConfig.host,
        port: config.redisConfig.port,
        enable_offline_queue: config.redisConfig.enable_offline_queue,
        db: (config.redisConfig.db + 1)
    });

    rateLimitPoints = 4; // requests
    rateLimitDuration = 10; // seconds
    rateLimiter = new RateLimiterRedis({
        storeClient: redisRatelimitClient,
        keyPrefix: "middleware",
        points: rateLimitPoints,
        duration: rateLimitDuration,
    });

    /**
     * @param {express.Request} req
     * @param {express.Response} res
     * @param {express.NextFunction} next
     */
    rateLimiterMiddleware = (req, res, next) => {
        let { host } = constructIP(req.ip, req.ips);
        let ipid = getIPIdentifierHex(host);

        rateLimiter.consume(ipid)
            .then((rateLimiterRes) => {
                res.set("Retry-After", (rateLimiterRes.msBeforeNext / 1000));
                res.set("X-Ratelimit-Limit", rateLimitPoints);
                res.set("X-Ratelimit-Remaining", rateLimiterRes.remainingPoints);
                res.set("X-Ratelimit-Reset", Math.round((Date.now() + rateLimiterRes.msBeforeNext) / 1000));
                next();
            })
            .catch((rateLimiterRes) => {
                res.set("Retry-After", (rateLimiterRes.msBeforeNext / 1000));
                res.set("X-Ratelimit-Limit", rateLimitPoints);
                res.set("X-Ratelimit-Remaining", rateLimiterRes.remainingPoints);
                res.set("X-Ratelimit-Reset", Math.round((Date.now() + rateLimiterRes.msBeforeNext) / 1000));
                res.set("Content-Type", "text/plain; charset=utf-8");
                res.status(429).send("Too Many Requests");
                handleLog(req, res, next);
            });
    };

    app = express();

    app.enable("trust proxy");
    app.disable("x-powered-by");
    app.set("query parser", false);
    app.set("env", "production");

    app.use((_, res, next) => {
        res.set("X-Powered-By", "new-iwhois");
        next();
    });
    app.use("/favicon.ico", (req, res, next) => {
        res.set("Content-Type", "text/plain; charset=utf-8");
        res.status(404).send("Sorry, can't find that!");
        handleLog(req, res, next, true);
    });
    app.get("/robots.txt", handleRobots);
    app.use(rateLimiterMiddleware);
    app.use((err, req, res, next) => {
        console.error(err.stack);
        res.set("Content-Type", "text/plain; charset=utf-8");
        res.status(500).send("Something broke!");
        handleLog(req, res, next, true);
    });
    app.get("/noscript.txt", (req, res, next) => {
        res.set("Content-Type", "text/plain; charset=utf-8");
        res.status(409).send(`Sorry, you have JavaScript disabled!

Available routes:
    /w/google.com           --> A recursive WHOIS on google.com
    /ww/google.com          --> A verbose recursive WHOIS on google.com
    /ripe/ORG-TCA23-RIPE    --> A WHOIS on ORG-TCA23-RIPE at RIPE DB
    /arin/a%20174           --> A WHOIS on "a 174" at ARIN
    /afrinic/AS33762        --> A WHOIS on AS33762 at AFRINIC
    /apnic/AS131073         --> A WHOIS on AS131073 at APNIC
    /lacnic/AS8167          --> A WHOIS on AS8167 at LACNIC
    /radb/1.1.1.0/24        --> A WHOIS on 1.1.1.0/24 at RADb`);
        handleLog(req, res, next, true);
    });
    app.get("/", handleRoot);
    app.get("/w/:whoisValue(*)", (req, res, next) => handleQuery(req, res, next, "recursive"));
    app.get("/ww/:whoisValue(*)", (req, res, next) => handleQuery(req, res, next, "recursive-verbose"));
    app.get("/ripe/:whoisValue(*)", (req, res, next) => handleQuery(req, res, next, "ripe"));
    app.get("/arin/:whoisValue(*)", (req, res, next) => handleQuery(req, res, next, "arin"));
    app.get("/afrinic/:whoisValue(*)", (req, res, next) => handleQuery(req, res, next, "afrinic"));
    app.get("/apnic/:whoisValue(*)", (req, res, next) => handleQuery(req, res, next, "apnic"));
    app.get("/lacnic/:whoisValue(*)", (req, res, next) => handleQuery(req, res, next, "lacnic"));
    app.get("/radb/:whoisValue(*)", (req, res, next) => handleQuery(req, res, next, "radb"));
    app.use((_, res, next) => {
        res.set("Content-Type", "text/plain; charset=utf-8");
        res.status(404).send("Sorry, can't find that!");
        next();
    });
    app.use(handleLog);

    app.listen(config.port, () => {
        console.log(`${Math.round(Date.now() / 1000)} "Server listening at port ${config.port}"`);
    });
};

process.on("SIGTERM", () => {
    console.warn(`${Math.round(Date.now() / 1000)} "SIGTERM signal received: closing HTTP server"`);
    if (app) app.close(() => {
        console.log(`${Math.round(Date.now() / 1000)} "HTTP server closed"`);
    });

    if (redisRatelimitClient) redisRatelimitClient.end(true);
    if (redisCacheClient) redisCacheClient.end(true);
});

main();
