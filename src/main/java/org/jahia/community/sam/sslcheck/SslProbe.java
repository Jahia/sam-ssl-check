package org.jahia.community.sam.sslcheck;

import java.io.IOException;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import javax.jcr.RepositoryException;
import javax.net.ssl.HttpsURLConnection;
import org.jahia.modules.sam.Probe;
import org.jahia.modules.sam.ProbeStatus;
import org.osgi.service.component.annotations.Component;

import org.jahia.modules.sam.ProbeSeverity;
import org.jahia.services.content.decorator.JCRSiteNode;
import org.jahia.services.sites.JahiaSitesService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(immediate = true, service = Probe.class)
public class SslProbe implements Probe {

    private static final Logger LOGGER = LoggerFactory.getLogger(SslProbe.class);
    private int nbDays = 7;

    @Override
    public String getName() {
        return "SSLCheck";
    }

    @Override
    public String getDescription() {
        return "Checking the SSL certificates are valid and are not going to expire";
    }

    @Override
    public ProbeStatus getStatus() {
        ProbeStatus status;
        final Date currentDate = new Date();
        final Calendar calendar = new GregorianCalendar();
        calendar.setTime(currentDate);
        calendar.add(Calendar.DAY_OF_YEAR, nbDays);
        try {
            boolean allSslValid = true;
            final JahiaSitesService jahiaSitesService = JahiaSitesService.getInstance();
            final List<String> invalidSsl = new ArrayList<>();
            for (JCRSiteNode siteNode : jahiaSitesService.getSitesNodeList()) {
                final List<String> siteInvalidSsl = new ArrayList<>();
                boolean siteSslValid = true;
                final List<String> hostnames = new ArrayList<>();
                hostnames.add(siteNode.getServerName());
                hostnames.addAll(siteNode.getServerNameAliases());
                for (String hostname : hostnames) {
                    if (!"localhost".equals(hostname)) {
                        final boolean isValidSsl = checkHostname(hostname, calendar);
                        if (!isValidSsl) {
                            siteSslValid = false;
                            siteInvalidSsl.add(hostname);
                        }
                    }
                }
                if (!siteSslValid) {
                    allSslValid = false;
                    invalidSsl.add(siteNode.getSiteKey() + ": " + siteInvalidSsl.toString());
                }
            }
            if (allSslValid) {
                status = new ProbeStatus("SSL certificates are valid", ProbeStatus.Health.GREEN);
            } else {
                status = new ProbeStatus(String.format("The following certificates are invalid or are going to expire in less than %s days: %s", nbDays, invalidSsl.toString()), ProbeStatus.Health.RED);
            }
        } catch (RepositoryException ex) {
            final String msg = "Impossible to check the SSL certificates";
            status = new ProbeStatus(msg, ProbeStatus.Health.RED);
            LOGGER.error(msg, ex);
        }
        return status;
    }

    @Override
    public ProbeSeverity getDefaultSeverity() {
        return ProbeSeverity.HIGH;
    }

    private boolean checkHostname(String hostname, Calendar calendar) {
        boolean result = true;

        try {
            final URL url = new URL("https://" + hostname);
            final HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();
            for (Certificate certificate : conn.getServerCertificates()) {
                final X509Certificate xCertificate = (X509Certificate) certificate;
                final List<String> validHostnames = new ArrayList<>();
                validHostnames.add(xCertificate.getSubjectDN().getName());
                final Collection<List<?>> alternativeNames = xCertificate.getSubjectAlternativeNames();
                if (alternativeNames != null) {
                    final Iterator<List<?>> alternativeNamesIterator = alternativeNames.iterator();
                    while (alternativeNamesIterator.hasNext()) {
                        validHostnames.add((String) alternativeNamesIterator.next().get(1));
                    }
                }
                if (validHostnames.contains(hostname)) {
                    result = !calendar.after(xCertificate.getNotAfter());
                    break;
                } else {
                    result = false;
                }

            }
        } catch (IOException | CertificateParsingException ex) {
            result = false;
            LOGGER.debug(String.format("Impossible to check %s", hostname), ex);
        }
        return result;
    }

    @Override
    public void setConfig(Map<String, Object> config) {
        if (config.containsKey("nb_days")) {
            nbDays = Integer.parseInt("nb_days");
        }
    }
}
