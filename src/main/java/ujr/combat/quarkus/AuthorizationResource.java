package ujr.combat.quarkus;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.UUID;

import javax.annotation.security.PermitAll;
import javax.enterprise.context.RequestScoped;
import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import io.quarkus.arc.profile.IfBuildProfile;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.build.JwtClaimsBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@IfBuildProfile("auth")
@Path("/api/auth")
@RequestScoped
public class AuthorizationResource {
	private static final Logger log = LoggerFactory.getLogger(AuthorizationResource.class);

	@POST
	@PermitAll
	@Produces(MediaType.APPLICATION_JSON)
	@Consumes(MediaType.APPLICATION_JSON)
	public Response authorize(@Valid AuthorizationDto authorizationDto) throws Exception {
		String token = TokenUtils.getInstance().generateTokenString(authorizationDto);
		return Response.ok().entity(Collections.singletonMap("token", token)).build();
	}

	public static class TokenUtils {
		private static TokenUtils instance;
		private TokenUtils() {}

		/**
		 * Utility method to generate a JWT string from a JSON resource file that is signed by the privateKey.pem
		 * test resource key, possibly with invalid fields.
		 *
		 * @param authorizationDto - dto request
		 * @return the JWT string
		 * @throws Exception on parse failure
		 */
		public String generateTokenString(AuthorizationDto authorizationDto)
				throws Exception {
			// Use the test private key associated with the test public key for a valid signature
			PrivateKey pk = readPrivateKey("/META-INF/resources/privateKey.pem");
			return generateTokenString(pk, "privateKey.pem", authorizationDto);
		}

		public String generateTokenString(PrivateKey privateKey, String kid,
				AuthorizationDto authorizationDto) {

			JwtClaimsBuilder claims = Jwt.claims();
			long currentTimeInSecs = currentTimeInSecs();
			long exp = currentTimeInSecs + 300;

			claims.claim("jti", UUID.randomUUID());
			claims.claim("authorities", Arrays.asList(authorizationDto.roles));
			claims.issuedAt(currentTimeInSecs);
			claims.expiresAt(exp);
			claims.claim("scope", Arrays.asList("read"));
			claims.subject(authorizationDto.user);
			claims.issuer("jwt");
			claims.claim("type", "access");
			return claims.jws().signatureKeyId(kid).sign(privateKey);
		}

		/**
		 * Read a PEM encoded private key from the classpath
		 *
		 * @param pemResName - key file resource name
		 * @return PrivateKey
		 * @throws Exception on decode failure
		 */
		public PrivateKey readPrivateKey(final String pemResName) throws Exception {
			try (InputStream contentIS = TokenUtils.class.getResourceAsStream(pemResName)) {
				byte[] tmp = new byte[4096];
				int length = contentIS.read(tmp);
				return decodePrivateKey(new String(tmp, 0, length, "UTF-8"));
			}
		}

		/**
		 * Decode a PEM encoded private key string to an RSA PrivateKey
		 *
		 * @param pemEncoded - PEM string for private key
		 * @return PrivateKey
		 * @throws Exception on decode failure
		 */
		public PrivateKey decodePrivateKey(final String pemEncoded) throws Exception {
			byte[] encodedBytes = toEncodedBytes(pemEncoded);

			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePrivate(keySpec);
		}

		private byte[] toEncodedBytes(final String pemEncoded) {
			return Base64.getDecoder().decode(removeBeginEnd(pemEncoded));
		}

		private String removeBeginEnd(String pem) {
			pem = pem.replaceAll("-----BEGIN (.*)-----", "");
			pem = pem.replaceAll("-----END (.*)----", "");
			pem = pem.replaceAll("\r\n", "");
			pem = pem.replaceAll("\n", "");
			return pem.trim();
		}

		/**
		 * @return the current time in seconds since epoch
		 */
		public int currentTimeInSecs() {
			long currentTimeMS = System.currentTimeMillis();
			return (int) (currentTimeMS / 1000);
		}

		public static TokenUtils getInstance() {
			if (instance == null) {
				try {
					KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
					kpg.initialize(2048);
					KeyPair kp = kpg.generateKeyPair();
					Key pub = kp.getPublic();
					Key pvt = kp.getPrivate();

					Base64.Encoder encoder = Base64.getEncoder();

					File privateKey = new File(AuthorizationResource.class.getResource("/META-INF/resources").getFile(), "privateKey.pem");
					Files.write(privateKey.toPath(),
							Arrays.asList("-----BEGIN PRIVATE KEY-----", encoder.encodeToString(pvt.getEncoded()), "-----END PRIVATE KEY-----"));
					File publicKey = new File(AuthorizationResource.class.getResource("/META-INF/resources").getFile(), "publicKey.pem");
					Files.write(publicKey.toPath(),
							Arrays.asList("-----BEGIN PUBLIC KEY-----", encoder.encodeToString(pub.getEncoded()), "-----END PRIVATE KEY-----"));
					instance = new TokenUtils();
				} catch (Exception e) {
					log.error("Error generate cert", e);
					throw new RuntimeException(e);
				}
			}
			return instance;
		}
	}

	public static class AuthorizationDto {
		@NotBlank
		private String user;
		@NotEmpty
		private String[] roles;

		public String getUser() {
			return user;
		}

		public void setUser(String user) {
			this.user = user;
		}

		public String[] getRoles() {
			return roles;
		}

		public void setRoles(String[] roles) {
			this.roles = roles;
		}
	}

}
