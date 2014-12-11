var url = require('url');
var fs = require('fs');
var http = require('http');
var https = require('https');
var crypto = require('crypto');
var util = require('util');

module.exports = {

    requestTicket: function (req, res, profile, certificate, proxyRestUri, targetId) {

        //Get and verify parameters
        certificate = certificate || {'filename': './client.pfx', 'passphrase': ''};
        proxyRestUri = proxyRestUri || url.parse(req.url, true).query.proxyRestUri;
        targetId = targetId || url.parse(req.url, true).query.targetId;

        if (!proxyRestUri || !targetId || !profile.UserId) {
            res.end("Missing parameters");
            return;
        }

        try {
            var cert = fs.readFileSync(certificate.filename);
        } catch (e) {
            res.end("Missing client certificate");
            return;
        }

        //Configure parameters for the ticket request
        var xrfkey = this.generateXrfkey();
        var options = {
            host: url.parse(proxyRestUri).hostname,
            port: url.parse(proxyRestUri).port,
            path: url.parse(proxyRestUri).path + '/ticket?xrfkey=' + xrfkey,
            method: 'POST',
            headers: {'X-Qlik-Xrfkey': xrfkey, 'Content-Type': 'application/json'},
            pfx: cert,
            passphrase: certificate.passphrase,
            rejectUnauthorized: false,
            agent: false
        };

        //Send ticket request
        var ticketreq = https.request(options, function (ticketres) {
            ticketres.on('data', function (d) {
                //Parse ticket response
                var ticket = JSON.parse(d.toString());

                //Build redirect including ticket
                if (ticket.TargetUri.indexOf("?") > 0) {
                    redirectURI = ticket.TargetUri + '&QlikTicket=' + ticket.Ticket;
                } else {
                    redirectURI = ticket.TargetUri + '?QlikTicket=' + ticket.Ticket;
                }

                res.writeHead(302, {"Location": redirectURI});
                res.end();
            });
        });

        //Send JSON request for ticket
        var jsonrequest = JSON.stringify({
            'UserDirectory': profile.UserDirectory,
            'UserId': profile.UserId,
            'Attributes': profile.Attributes,
            'TargetId': targetId.toString()
        });
        ticketreq.write(jsonrequest);
        ticketreq.end();

        ticketreq.on('error', function (e) {
            console.error('Error' + e);
        });
    },

    generateXrfkey: function (size, chars) {

        size = size || 16;
        chars = chars || "abcdefghijklmnopqrstuwxyzABCDEFGHIJKLMNOPQRSTUWXYZ0123456789";

        var rnd = crypto.randomBytes(size), value = new Array(size), len = chars.length;

        for (var i = 0; i < size; i++) {
            value[i] = chars[rnd[i] % len]
        };

        return value.join('');
    },

    requestWebTicket: function (req, res, profile) {

        var host = profile.Host || "/";
        var tryUrl = profile.Document ? '/QvAjaxZfc/opendoc.htm?document=' + profile.Document : "/QlikView"
        var backUrl = profile.BackUrl || "";

        var options = {
            host: url.parse(host).hostname,
            port: url.parse(host).port,
            path: '/QvAJAXZfc/GetWebTicket.aspx',
            method: 'POST'
        };

        var groups = "";
        if (profile.Groups.length > 0) {
            groups = "<GroupList>";
            for (var i = profile.Groups.length - 1; i >= 0; i--) {
                groups += '<string>' + profile.Groups[i] + '</string>';
            };
            groups += "</GroupList><GroupsIsNames>true</GroupsIsNames>";
        }

        var user = profile.UserDirectory + (profile.UserDirectory ? '\\' : '') + profile.UserId;

        var xml = util.format('<Global method="GetWebTicket"><UserId>%s</UserId>%s</Global>', user, groups);

        var ticketreq = http.request(options, function (ticketres) {
            ticketres.on('data', function (d) {
                //Parse ticket response
                var ticket = d.toString().match('<_retval_>(.*)</_retval_>')[1];
                if (ticket.length == 40) {
                    var redirectURI = util.format('%s/QvAJAXZfc/Authenticate.aspx?type=html&webticket=%s&try=%s&back=%s', host, ticket, tryUrl, backUrl)
                    res.writeHead(302, {"Location": redirectURI});
                    res.end();
                }
                else {
                    res.write(d.toString);
                    res.end();
                }
            });
        });

        ticketreq.write(xml);
        ticketreq.end();

        ticketreq.on('error', function (e) {
            console.error('Error' + e);
        });
    }
};
