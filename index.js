var os = require("os");
var url = require('url');
var fs = require('fs');
var http = require('http');
var https = require('https');
var crypto = require('crypto');
var util = require('util');
var edge = require('edge');

function getFileRealPath(s) {
    try {
        return fs.realpathSync(s);
    } catch (e) {
        return false;
    }
}

module.exports = {

    init: function (req, res) {

        //Store targetId and proxyRestUri in a global object
        if (url.parse(req.url, true).query.targetId != undefined) {
            global.qlikAuthSession = {
                "targetId": url.parse(req.url, true).query.targetId,
                "proxyRestUri": url.parse(req.url, true).query.proxyRestUri
            };
            //cut last slash if there is one
            if (global.qlikAuthSession.proxyRestUri.substr(-1) === '/') {
                global.qlikAuthSession.proxyRestUri = global.qlikAuthSession.proxyRestUri.substr(0, global.qlikAuthSession.proxyRestUri.length - 1);
            }
        }
    },

    requestTicket: function (req, res, profile, options) {

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

        //Configure parameters for the ticket request
        var xrfkey = this.generateXrfkey();
        var settings = {
            host: url.parse(options.ProxyRestUri).hostname,
            port: url.parse(options.ProxyRestUri).port,
            path: url.parse(options.ProxyRestUri).path + '/ticket?xrfkey=' + xrfkey,
            method: 'POST',
            headers: {
                'X-Qlik-Xrfkey': xrfkey,
                'Content-Type': 'application/json'
            },
            passphrase: options.PassPhrase,
            rejectUnauthorized: false,
            agent: false
        };

        //First try Windows certificate store for local client cert
        if (os.platform() == "win32") {
            var exportCertificate = edge.func(function () {
                /*
                                using System;
                                using System.Threading.Tasks;
                                using System.Linq;
                                using System.Security.Cryptography.X509Certificates;
                             
                                public class Startup
                                {
                                    public async Task<object> Invoke(dynamic input)
                                    {
                                        X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                                        store.Open(OpenFlags.ReadOnly);
                                        var certificate_ = store.Certificates.Cast<X509Certificate2>().FirstOrDefault(c => c.FriendlyName == "QlikClient");
                                        store.Close();
                                        return certificate_ != null ? Convert.ToBase64String(certificate_.Export(X509ContentType.Pfx, "jfB0ndtJ2yoqrqTzPwYi")) : null;
                                    }
                                }
                            */
            });

            exportCertificate(null, function (error, result) {
                if (error) {
                    res.send(error);
                    return
                };
                if (result != null) {
                    settings.pfx = new Buffer(result, 'base64');;
                    settings.passphrase = "jfB0ndtJ2yoqrqTzPwYi";
                }
            });
        }

        if (settings.pfx == undefined) {
            //Try client.pfx and client.pem as defaults
            var cert = getFileRealPath(options.Certificate)
            var certKey = false;

            if (!cert)
                cert = getFileRealPath("./client.pem")
            if (cert && cert.indexOf(".pem") > 0)
                certKey = getFileRealPath(options.CertificateKey)
            if (!cert || cert && cert.indexOf(".pem") > 0 && !certKey) {
                res.end('Missing client certificate or key');
                return;
            }

            //Read certificates
            try {
                if (cert.indexOf(".pem") > 0) {
                    settings.cert = fs.readFileSync(cert);
                    settings.key = fs.readFileSync(certKey);
                } else {
                    settings.pfx = fs.readFileSync(cert);
                }
            } catch (e) {
                res.end('Error reading client certificate or key');
                return;
            }
        }

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

                res.writeHead(302, {
                    'Location': redirectURI
                });
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
            headers: {
                'X-Qlik-Xrfkey': xrfkey,
                'Content-Type': 'application/json'
            },
            passphrase: options.PassPhrase,
            rejectUnauthorized: false,
            agent: false
        };

        //Try client.pfx and client.pem as defaults
        var cert = getFileRealPath(options.Certificate)
        var certKey = false;

        if (!cert)
            cert = getFileRealPath("./client.pem")
        if (cert && cert.indexOf(".pem") > 0)
            certKey = getFileRealPath(options.CertificateKey)
        if (!cert || cert && cert.indexOf(".pem") > 0 && !certKey) {
            console.log('Missing client certificate or key');
            return;
        }

        //Read certificates
        try {
            if (cert.indexOf(".pem") > 0) {
                settings.cert = fs.readFileSync(options.Certificate);
                settings.key = fs.readFileSync(options.CertificateKey);
            } else {
                settings.pfx = fs.readFileSync(options.Certificate);
            }
        } catch (e) {
            res.end('Error reading client certificate or key');
            return;
        }

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

        var rnd = crypto.randomBytes(size),
            value = new Array(size),
            len = chars.length;

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
                        res.writeHead(302, {
                            'Location': redirectURI
                        });
                        res.end();
                    } else {
                        res.write(d.toString);
                        res.end();
                    }
                } catch (e) {
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