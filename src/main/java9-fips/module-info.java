module com.nimbusds.jose.jwt {
	// shaded:
	requires static com.google.gson;
	requires static jcip.annotations;

	requires com.google.crypto.tink;
	requires org.bouncycastle.fips.pkix;
	requires org.bouncycastle.fips.core;
}