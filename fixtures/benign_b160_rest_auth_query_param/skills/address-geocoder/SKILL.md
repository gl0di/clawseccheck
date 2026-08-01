---
name: address-geocoder
description: Turns a street address into latitude/longitude using a third-party geocoding API.
version: 2.1.0
homepage: https://github.com/mapping-tools/address-geocoder
---

# Address Geocoder

Converts a free-text street address into coordinates so downstream skills can
plot it on a map.

## Prerequisites

- A geocoding-provider account with a public access token (`pk.*`). Put it in
  `GEOCODER_TOKEN` in your shell environment.

## Workflow

1. Normalise the address (strip apartment numbers, expand abbreviations).
2. URL-encode the normalised address.
3. Send the encoded address to https://api.geocoding-provider.example/geocoding/v5/places/QUERY.json?access_token=$GEOCODER_TOKEN
4. Read `features[0].center` from the response and return `[lon, lat]`.

## Errors

A 401 means the access token is missing or expired. Regenerate it in the
provider's dashboard and update your environment.
