-- Recognized ASN.1 OIDs.

local asn = require("tls13.asn")

local lib = {}

lib.root = asn.makeOid()

lib.ccitt = lib.root.ccitt(0)
-- this one has a fun bit of history
lib.domainComponent = lib
  .ccitt
  .data(9)
  .pss(2342)
  .ucl(19200300)
  .pilot(100)
  .pilotAttributeType(1)
  .domainComponent(25)

lib.iso = lib.root.iso(1)

lib.internet = lib
  .iso
  .identifiedOrganization(3)
  .dod(6)
  .internet(1)

lib.pkix = lib
  .internet
  .security(5)
  .mechanisms(5)
  .pkix(7)

lib.pkix.pe(1)
lib.pkix.pe.authorityInfoAccess(1)
lib.pkix.pe.subjectInfoAccess(11)

lib.pkix.qt(2)
lib.pkix.qt.cps(1)
lib.pkix.qt.unotice(2)

lib.pkix.kp(3)
lib.pkix.kp.serverAuth(1)
lib.pkix.kp.clientAuth(2)
lib.pkix.kp.codeSigning(3)
lib.pkix.kp.emailProtection(4)
lib.pkix.kp.timeStamping(5)
lib.pkix.kp.OCSPSigning(9)

lib.pkix.ad(48)
lib.pkix.ad.ocsp(1)
lib.pkix.ad.caIssuers(2)
lib.pkix.ad.timeStamping(3)
lib.pkix.ad.caRepository(5)

lib.x25519 = lib.iso.identifiedOrganization.thawte(101).x25519(110)
lib.edDSA25519 = lib.iso.identifiedOrganization.thawte(101).edDSA25519(112)

lib.pkcs1 = lib
  .iso
  .memberBody(2)
  .us(840)
  .rsadsi(113549)
  .pkcs(1)
  .pkcs1(1)

lib.pkcs1.rsaEncryption(1)
lib.pkcs1.sha1WithRSAEncryption(5)
lib.pkcs1.mgf1(8)
lib.pkcs1.rsassaPss(10)
lib.pkcs1.sha256WithRSAEncryption(11)
lib.pkcs1.sha384WithRSAEncryption(12)
lib.pkcs1.sha512WithRSAEncryption(13)

lib.ansiX962 = lib.iso.memberBody.us(840).ansiX962(10045)

lib.ansiX962.keyType(2).ecPublicKey(1)

lib.ansiX962.curves(3).prime(1).prime256r1(7)
lib.ansiX962.curves(3).prime(1).prime384r1(34)

lib.ansiX962.signatures(4).ecdsaWithSHA2(3).ecdsaWithSHA256(2)
lib.ansiX962.signatures(4).ecdsaWithSHA2(3).ecdsaWithSHA384(3)
lib.ansiX962.signatures(4).ecdsaWithSHA2(3).ecdsaWithSHA512(4)

lib.sha1 = lib
  .iso
  .identifiedOrganization(3)
  .oiw(14)
  .secsig(3)
  .algorithms(3)
  .sha1(26)

lib.jointIsoCcitt = lib.root.jointIsoCcitt(2)

lib.ce = lib.jointIsoCcitt.ds(5).certificateExtension(29)
lib.ce.subjectDirectoryAttributes(9)
lib.ce.subjectKeyIdentifier(14)
lib.ce.keyUsage(15)
lib.ce.subjectAltName(17)
lib.ce.issuerAltName(18)
lib.ce.basicConstraints(19)
lib.ce.nameConstraints(30)
lib.ce.cRLDistributionPoints(31)
lib.ce.certificatePolicies(32)
lib.ce.certificatePolicies.anyPolicy(0)
lib.ce.policyMappings(33)
lib.ce.authorityKeyIdentifier(35)
lib.ce.policyConstraints(36)
lib.ce.extKeyUsage(37)
lib.ce.extKeyUsage.anyExtendedKeyUsage(0)
lib.ce.inhibitAnyPolicy(54)

lib.at = lib.jointIsoCcitt.ds.at(4)
lib.at.commonName(3)
lib.at.surname(4)
lib.at.serialNumber(5)
lib.at.countryName(6)
lib.at.localityName(7)
lib.at.stateOrProvinceName(8)
lib.at.organizationName(10)
lib.at.organizationalUnitName(11)
lib.at.title(12)
lib.at.name(41)
lib.at.givenName(42)
lib.at.initials(43)
lib.at.generationQualifier(44)
lib.at.dnQualifier(46)
lib.at.pseudonym(65)

lib.hashalgs = lib
  .jointIsoCcitt
  .country(16)
  .us(840)
  .organization(1)
  .gov(101)
  .csor(3)
  .nistalgorithm(4)
  .hashalgs(2)

lib.hashalgs.sha256(1)
lib.hashalgs.sha384(2)
lib.hashalgs.sha512(3)

return lib
