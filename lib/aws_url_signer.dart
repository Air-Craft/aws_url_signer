library aws_url_signer;

import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:intl/intl.dart';

String _buildQueryString(
    {String accessKey,
    String sessionToken,
    String algorithm,
    String amzDate,
    String credentialScope,
    String expires = "15",
    Map<String, String> additionalQuery
    }) {
  final queryString = {
    "X-Amz-Algorithm": algorithm,
    "X-Amz-Credential": Uri.encodeComponent(accessKey + "/" + credentialScope),
    "X-Amz-Date": amzDate,
    "X-Amz-Expires": expires,
    "X-Amz-SignedHeaders": "host",
  };
  if (sessionToken != null) {
    queryString["X-Amz-Security-Token"] = Uri.encodeComponent(sessionToken);
  }
  if (additionalQuery is Map<String, String>) {
    queryString.addAll(additionalQuery);
  }

  final canonicalQueryString =
      queryString.entries.map((e) => "${e.key}=${e.value}").join("&");

  return canonicalQueryString;
}

String getSignedWebSocketUrl(
    {String apiId,
    String service = "execute-api",
    String port = '8443',
    String region,
    Map<String, String> queryParams,
    String stage,
    String accessKey,
    String secretKey,
    String sessionToken,
    bool debug=false}) {
  final method = "GET";
  final host = "$apiId.$region.amazonaws.com" + (port != null ? ":$port" : "");
  final canonicalUri = "/$stage";
  final now = DateTime.now().toUtc();

  final amzDate = DateFormat('yyyyMMddTHHmmss').format(now) + "Z";
  final dateStamp = DateFormat('yyyyMMdd').format(now);
  final canonicalHeaders = "host:" + host + "\n";
  final signedHeaders = "host";
  final algorithm = "AWS4-HMAC-SHA256";

  final credentialScopeArray = [
    dateStamp,
    region,
    service,
    'aws4_request',
  ];

  final credentialScope = credentialScopeArray.join("/");

  var canonicalQueryString = _buildQueryString(
    accessKey: accessKey,
    sessionToken: sessionToken,
    algorithm: algorithm,
    amzDate: amzDate,
    credentialScope: credentialScope,
    additionalQuery: queryParams
  );

  final payloadHash = sha256.convert(utf8.encode("")).toString();

  final canonicalRequest = [
    method,
    canonicalUri,
    canonicalQueryString,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  if (debug) {
    print("\nCanonical Request:");
    print(canonicalRequest);
    print("\n");
  }

  final stringToSign = [
    algorithm,
    amzDate,
    credentialScope,
    sha256.convert(utf8.encode(canonicalRequest)).toString(),
  ].join('\n');

  if (debug) {
    print("\nString-to-Sign:");
    print(stringToSign);
    print("\n");
  }


  final signingKey = credentialScopeArray.fold(utf8.encode('AWS4$secretKey'),
      (List<int> key, String s) {
    final hmac = Hmac(sha256, key);
    return hmac.convert(utf8.encode(s)).bytes;
  });

  final signature =
      Hmac(sha256, signingKey).convert(utf8.encode(stringToSign)).toString();
  canonicalQueryString += ("&X-Amz-Signature=" + signature);
  final requestUrl = "wss://$host/$stage?$canonicalQueryString";
  return requestUrl;
}
