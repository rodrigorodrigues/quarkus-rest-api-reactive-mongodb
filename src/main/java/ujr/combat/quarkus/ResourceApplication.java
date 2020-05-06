package ujr.combat.quarkus;

import javax.ws.rs.core.Application;

import org.eclipse.microprofile.openapi.annotations.OpenAPIDefinition;
import org.eclipse.microprofile.openapi.annotations.enums.SecuritySchemeIn;
import org.eclipse.microprofile.openapi.annotations.enums.SecuritySchemeType;
import org.eclipse.microprofile.openapi.annotations.info.Contact;
import org.eclipse.microprofile.openapi.annotations.info.Info;
import org.eclipse.microprofile.openapi.annotations.info.License;
import org.eclipse.microprofile.openapi.annotations.security.SecurityRequirement;
import org.eclipse.microprofile.openapi.annotations.security.SecurityScheme;
import org.eclipse.microprofile.openapi.annotations.security.SecuritySchemes;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

@OpenAPIDefinition(
		tags = {
				@Tag(name="company", description="Operations related to companies")
		},
		info = @Info(
				title="Example API",
				version = "0.0.1",
				contact = @Contact(
						name = "Example API Support",
						url = "http://exampleurl.com/contact",
						email = "techsupport@example.com"),
				license = @License(
						name = "Apache 2.0",
						url = "http://www.apache.org/licenses/LICENSE-2.0.html")),
		security = @SecurityRequirement(name = "api_key")
)
@SecuritySchemes(@SecurityScheme(securitySchemeName = "api_key",
		type = SecuritySchemeType.APIKEY,
		apiKeyName = "Authorization",
		in = SecuritySchemeIn.HEADER)
)
public class ResourceApplication extends Application {
}
