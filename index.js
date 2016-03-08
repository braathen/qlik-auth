var url = require('url');
var fs = require('fs');
var http = require('http');
var https = require('https');
var crypto = require('crypto');
var util = require('util');
var _ = require("underscore");

function getFileRealPath(s) {
    try {
        return fs.realpathSync(s);
    } catch (e) {
        return null;
    }
}

function getCertificates(cert, certKey) {
    var certificate = {};
    var _cert = null;
    var _certKey = null;

    var files = ["client.pem", "client.pfx", "C:\\ProgramData\\Qlik\\Sense\\Repository\\Exported Certificates\\.Local Certificates\\client.pem"];
    files.unshift(cert);
    files = _.uniq(files);

    for (var obj in files) {
        _cert = getFileRealPath(files[obj]);
        if (_cert != null)
            break;
    }

    if (_cert != null) {
        try {
            if (_cert.toLowerCase().indexOf(".pem") > 0) {
                // .pem
                var files = ["client_key.pem", "C:\\ProgramData\\Qlik\\Sense\\Repository\\Exported Certificates\\.Local Certificates\\client_key.pem"];
                files.unshift(certKey);
                files = _.uniq(files);

                for (var obj in files) {
                    _certKey = getFileRealPath(files[obj]);

                    if (certKey != null) {
                        certificate.cert = fs.readFileSync(_cert);
                        certificate.key = fs.readFileSync(_certKey);
                        break;
                    }
                }
            } else {
                // .pfx
                certificate.pfx = fs.readFileSync(_cert);
            }
        } catch (e) {
            // nothing to see here...
        }
    }
    return certificate;
}


module.exports = {

    init: function (req, res) {

        //Store targetId and proxyRestUri in a global object
        if (url.parse(req.url, true).query.targetId != undefined) {
            global.qlikAuthSession = {
                "targetId": url.parse(req.url, true).query.targetId,
                "proxyRestUri": url.parse(req.url, true).query.proxyRestUri
            };
        }
    },

    requestTicket: function (req, res, profile, options) {

        if (!options)
            var options = {};

        //Get and verify parameters
        options.Certificate = options.Certificate || './client.pem';
        options.CertificateKey = options.CertificateKey || './client_key.pem';
        options.PassPhrase = options.PassPhrase || '';
        options.ProxyRestUri = options.ProxyRestUri || url.parse(req.url, true).query.proxyRestUri;
        options.TargetId = options.TargetId || url.parse(req.url, true).query.targetId;

        if (global.qlikAuthSession) {
            options.ProxyRestUri = global.qlikAuthSession.proxyRestUri;
            options.TargetId = global.qlikAuthSession.targetId;
        }

        if (!options.ProxyRestUri || !options.TargetId || !profile.UserId) {
            res.end('Missing parameters');
            return;
        }

        //Configure parameters for the ticket request
        var xrfkey = this.generateXrfkey();
        var settings = {
            host: url.parse(options.ProxyRestUri).hostname,
            port: url.parse(options.ProxyRestUri).port,
            path: url.parse(options.ProxyRestUri).path + '/ticket?xrfkey=' + xrfkey,
            method: 'POST',
            headers: {'X-Qlik-Xrfkey': xrfkey, 'Content-Type': 'application/json'},
            passphrase: options.PassPhrase,
            rejectUnauthorized: false,
            agent: false
        };

        //Locate certificate
        var cert = getCertificates(options.Certificate, options.CertificateKey);
        settings = _.extend(settings, cert);

        //Send ticket request
        var ticketreq = https.request(settings, function (ticketres) {
            ticketres.on('data', function (d) {
                //Parse ticket response
                var ticket = JSON.parse(d.toString());

                //Build redirect including ticket
                if (ticket.TargetUri.indexOf("?") > 0) {
                    redirectURI = ticket.TargetUri + '&QlikTicket=' + ticket.Ticket;
                } else {
                    redirectURI = ticket.TargetUri + '?QlikTicket=' + ticket.Ticket;
                }

                res.writeHead(302, {'Location': redirectURI});
                res.end();
            });
        });

        //Send JSON request for ticket
        var jsonrequest = JSON.stringify({
            'UserDirectory': profile.UserDirectory,
            'UserId': profile.UserId,
            'Attributes': profile.Attributes || [],
            'TargetId': options.TargetId.toString()
        });
        ticketreq.write(jsonrequest);
        ticketreq.end();

        ticketreq.on('error', function (e) {
            res.end(e.toString());
        });
    },

    // ==========================================================================
    // NOTE: The session stuff is a work in progress.... and not really finished.
    // ==========================================================================

    addSession: function (req, res, profile, options) {
        sessionHelper(req, res, profile, options, 'POST');
    },

    getSession: function (req, res, profile, options) {
        sessionHelper(req, res, profile, options, 'GET');
    },

    deleteSession: function (req, res, profile, options) {
        sessionHelper(req, res, profile, options, 'DELETE');
    },

    sessionHelper: function (req, res, profile, options, method) {

        if (!options)
            var options = {};

        //Get and verify parameters
        options.Certificate = options.Certificate || './client.pfx';
        options.CertificateKey = options.CertificateKey || './client_key.pem';
        options.PassPhrase = options.PassPhrase || '';
        options.ProxyRestUri = options.ProxyRestUri || url.parse(req.url, true).query.proxyRestUri;
        options.TargetId = options.TargetId || url.parse(req.url, true).query.targetId;

        if (global.qlikAuthSession) {
            options.ProxyRestUri = global.qlikAuthSession.proxyRestUri;
            options.TargetId = global.qlikAuthSession.targetId;
        }

        if (!options.ProxyRestUri || !options.TargetId || !profile.UserId) {
            res.end('Missing parameters');
            return;
        }

        //Configure parameters for the session request
        var xrfkey = this.generateXrfkey();
        var settings = {
            host: url.parse(options.ProxyRestUri).hostname,
            port: url.parse(options.ProxyRestUri).port,
            path: url.parse(options.ProxyRestUri).path + '/session?xrfkey=' + xrfkey,
            method: method,
            headers: {'X-Qlik-Xrfkey': xrfkey, 'Content-Type': 'application/json'},
            passphrase: options.PassPhrase,
            rejectUnauthorized: false,
            agent: false
        };

        //Locate certificate
        var cert = getCertificates(options.Certificate, options.CertificateKey);
        settings = _.extend(settings, cert);

        //Send session request
        var ticketreq = https.request(settings, function (ticketres) {
            ticketres.on('data', function (d) {
                //Parse session response
                var ticket = JSON.parse(d.toString());

                // //Build redirect including ticket
                // if (ticket.TargetUri.indexOf("?") > 0) {
                //     redirectURI = ticket.TargetUri + '&QlikTicket=' + ticket.Ticket;
                // } else {
                //     redirectURI = ticket.TargetUri + '?QlikTicket=' + ticket.Ticket;
                // }

                // res.writeHead(302, {'Location': redirectURI});
                // res.end();
            });
            console.log(ticketreq);
            console.log(settings);
        });

        //Send JSON request for ticket
        var jsonrequest = JSON.stringify({
            'UserDirectory': profile.UserDirectory,
            'UserId': profile.UserId,
            'Attributes': profile.Attributes || [],
            'TargetId': options.TargetId.toString()
        });
        ticketreq.write(jsonrequest);
        ticketreq.end();

        ticketreq.on('error', function (e) {
            console.error('Error' + e);
        });
    },

    generateXrfkey: function (size, chars) {

        size = size || 16;
        chars = chars || 'abcdefghijklmnopqrstuwxyzABCDEFGHIJKLMNOPQRSTUWXYZ0123456789';

        var rnd = crypto.randomBytes(size), value = new Array(size), len = chars.length;

        for (var i = 0; i < size; i++) {
            value[i] = chars[rnd[i] % len]
        };

        return value.join('');
    },

    requestWebTicket: function (req, res, profile, options) {

        if (!options)
            var options = {};

        //Get parameters
        options.Host = options.Host || 'http://localhost';
        options.TryUrl = options.TryUrl || '/QlikView'
        options.BackUrl = options.BackUrl || '';
        options.RedirectUrl = options.RedirectUrl || options.Host;
 
        var tryUrl = options.Document ? '/QvAjaxZfc/opendoc.htm?document=' + options.Document : options.TryUrl

        var settings = {
            host: url.parse(options.Host).hostname,
            port: url.parse(options.Host).port,
            path: '/QvAJAXZfc/GetWebTicket.aspx',
            method: 'POST'
        };

        //Configure groups
        var groups = '';
        if (profile.Groups && profile.Groups.length > 0) {
            groups = '<GroupList>';
            for (var i = profile.Groups.length - 1; i >= 0; i--) {
                groups += '<string>' + profile.Groups[i] + '</string>';
            };
            groups += '</GroupList><GroupsIsNames>true</GroupsIsNames>';
        }

        var user = profile.UserDirectory + (profile.UserDirectory ? '\\' : '') + profile.UserId;

        var body = util.format('<Global method="GetWebTicket"><UserId>%s</UserId>%s</Global>', user, groups);

        //Send webticket request
        var ticketreq = http.request(settings, function (ticketres) {
            ticketres.on('data', function (d) {
                try {
                    var ticket = d.toString().match('<_retval_>(.*)</_retval_>')[1];
                    if (ticket.length == 40) {
                        var redirectURI = util.format('%s/QvAJAXZfc/Authenticate.aspx?type=html&webticket=%s&try=%s&back=%s', options.RedirectUrl, ticket, tryUrl, options.BackUrl)
                        res.writeHead(302, {'Location': redirectURI});
                        res.end();
                    }
                    else {
                        res.write(d.toString);
                        res.end();
                    }
                }
                catch (e) {
                    res.write("Error retrieving webticket");
                    res.end();
                }
            });
        });

        ticketreq.write(body);
        ticketreq.end();

        ticketreq.on('error', function (e) {
            console.error('Error' + e);
        });
    }
};

