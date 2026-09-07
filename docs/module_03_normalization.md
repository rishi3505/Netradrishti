# Module 3: Event Normalization & Entity Resolution

## Purpose
The purpose of this module is to take the UnifiedSecurityEvent produced by Module 2 connectors and normalize its fields to a canonical form, followed by extracting and resolving entities (like IP, Hostname, User, Domain, etc.) using deterministic logic.

## Architecture
- **Normalization Engine**: Replaces non-standard values (e.g., uppercase IPs, trailing dots in domains) with standardized ones.
- **Consistency Validator**: Emits warnings if data contradicts itself (e.g. invalid hash lengths).
- **Entity Extractor**: Scans the normalized event and extracts raw entity representations.
- **Entity Resolver and Matcher**: Uses deterministic confidence scores (ranging from 0 to 100) to find matching existing entities in the database or creates new ones.
- **Normalization Pipeline**: Ties the whole process together.

## Normalization Rules Implemented
1. **IP Addresses**: Uses python `ipaddress` for IPv4/IPv6 canonicalization.
2. **Hostnames**: Lowercased. If FQDN, short hostname is extracted.
3. **Domains**: Lowercased, trailing dots stripped.
4. **Users**: Identifies domains in `DOMAIN\user` or `user@domain.com` formats.
5. **Hashes**: Validated for hex characters and correct lengths (md5=32, sha1=40, sha256=64).
6. **URLs**: Reconstructed into a normalized form using `urllib.parse`.

## Entity Resolution Logic
- **100 Confidence**: Exact Device ID match, exact IP match (for IP entities), exact hash match.
- **85 Confidence**: Same User and Domain match.
- **70+ Confidence**: Strong matches that result in linking/merging.
- **<70**: Weak matches that only result in aliases or relationships.

## APIs
- `POST /api/v1/entities/resolve`: Preview entity resolution logic for an extracted entity.
