module com.nimbusds.jose.jwt {
	// shaded:
	requires static com.google.gson;
	requires static jcip.annotations;

	requires com.google.crypto.tink;
	requires org.bouncycastle.pkix;
	requires org.bouncycastle.provider;
}