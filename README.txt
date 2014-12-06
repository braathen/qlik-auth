WHAT IS QLIK-AUTH?

  qlik-auth is an attempt of simplyfing custom authentication with the Qlik
  Sense and QlikView products. This module for Node.js takes care of the ticket
  request and redirection. It allows a developer to focus on obtaining the user
  profile, provide it in a function call, and the rest will be automated.

REQUIREMENTS

 - Node.js (including npm) <https://nodejs.org>

INSTALLATION

    npm install qlik-auth

SETUP FOR QLIK SENSE

  Typically a custom authentication module in Qlik Sense would be called
  through a virtual proxy. Refer to Qlik Sense documentation how to set this
  up and configure it properly to access your custom built module.

 - In the minimal example below a simple webserver is created with Node.js
   which listens on port 1337. This is the server and port you need to map in
   the virutal proxy configuration.

 - Export the client/server certificates from QMC and copy them to the same
   directory as your script. If it's necessary to provide a password, see the
   Advanced section below.

SETUP FOR QLIKVIEW

  QlikView would need to be configured for using webtickets, this includes
  changing Windows Authentication to Anonymous Authentication and configuring
  IP white lists as trust.

  QlikView support is coming soon!

EXAMPLE

  This is just a minimal example to demonstrate how simple it is to use the
  module. The code below should only be seen as a demonstration and a way to
  get started. Normally you would want to run the server as HTTPS.

    var http = require('http');
    var qlikauth = require('qlik-auth');
    http.createServer(function (req, res) {

      //Define user directory, user identity and attributes
      var profile = {
        'UserDirectory': 'QTSEL', 
        'UserId': 'rfn',
        'Attributes': []
      }

      //Make call for ticket request
      qlikauth.requestTicket(req, res, profile);

    }).listen(1337, '0.0.0.0');
    console.log('Server running at http://localhost:1337/');

ADVANCED USAGE

  The module exposes a function called requestTicket which has the following
  parameters:

    function(req, res, profile, certificate, proxyRestUri, targetId)

 - In case the certificate is password protected it's possible to provide both
   the location and filename of the certificate together with a passphrase. It
   could look like this:

     var certificate = {
       'filename': './certificates/client.pfx',
       'passphrase': 'MyVerySecretPassphrase'
     }

 - When Qlik Sense is redirecting to a custom authentication module it passes
   proxyRestUri and targetId as parameters. These are normally handled by the
   function automatically, but for scenarios where it might be necessary to
   redirect to another Identity Provider for example, these parameters must be
   stored away and supplied manually.
