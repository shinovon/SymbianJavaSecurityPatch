/*
* Copyright (c) 2008 Nokia Corporation and/or its subsidiary(-ies).
* All rights reserved.
* This component and the accompanying materials are made available
* under the terms of "Eclipse Public License v1.0"
* which accompanies this distribution, and is available
* at the URL "http://www.eclipse.org/legal/epl-v10.html".
*
* Initial Contributors:
* Nokia Corporation - initial contribution.
*
* Contributors:
*
* Description:
*
*/

package com.nokia.mj.impl.security.midp.authentication;

import com.nokia.mj.impl.utils.Uid;
import com.nokia.mj.impl.utils.Tokenizer;
import com.nokia.mj.impl.security.common.InstallerSecurityException;
import com.nokia.mj.impl.security.common.RuntimeSecurityException;
import com.nokia.mj.impl.utils.InstallerDetailedErrorMessage;
import com.nokia.mj.impl.utils.InstallerErrorMessage;
import com.nokia.mj.impl.utils.OtaStatusCode;
import com.nokia.mj.impl.security.utils.SecurityErrorMessage;
import com.nokia.mj.impl.security.utils.SecurityDetailedErrorMessage;
import com.nokia.mj.impl.security.utils.TelUtils;
import com.nokia.mj.impl.security.midp.common.AuthenticationCredentials;
import com.nokia.mj.impl.security.midp.common.AuthenticationInfo;
import com.nokia.mj.impl.security.midp.common.SecurityAttributes;
import com.nokia.mj.impl.security.common.Certificate;
import com.nokia.mj.impl.security.common.SecurityCommsMessages;
import com.nokia.mj.impl.security.midp.common.ProtectionDomain;
import com.nokia.mj.impl.security.midp.common.SigningCertificate;
import com.nokia.mj.impl.security.midp.common.SigningInfo;
import com.nokia.mj.impl.security.midp.storage.*;
import com.nokia.mj.impl.storage.StorageSession;
import com.nokia.mj.impl.rt.support.Jvm;
import com.nokia.mj.impl.rt.support.ApplicationInfo;
import com.nokia.mj.impl.security.utils.Logger;
import com.nokia.mj.impl.comms.CommsEndpoint;
import com.nokia.mj.impl.comms.CommsMessage;
import com.nokia.mj.impl.comms.exception.CommsException;
import com.nokia.mj.impl.fileutils.DriveUtilities;
import com.nokia.mj.impl.installer.utils.Log;
import com.nokia.mj.impl.fileutils.DriveInfo;
import java.util.Hashtable;
import java.util.Vector;
/**
 * MIDP authentication is build around X.509 Public Key Infrastructure so that
 * MIDlet suites are signed using public key certificates and therefore
 * authenticated by verifying the authenticity of the MIDlet suite's signing
 * certificates with the help of trusted (root) certificates.
 * As a result of authentication a MIDlet suite is bound to a protection domain
 * which will be used as a criteria for granting the MIDlet access to protected
 * functionality.
 * This class is used for authenticating MIDlet suites.
 */
public final class AuthenticationModule
{
    static
    {
    	Log.logOut("ForceDomain for Symbian^3 by Shinovon");
        Log.logOut("Forced protection domain: " + getForcedDomainName());
        Jvm.loadSystemLibrary("javasecurity");
    }
    
    public static String getForcedDomainName() {
    	String domain = getForcedDomainCategory();
    	if(domain.equalsIgnoreCase(ApplicationInfo.MANUFACTURER_DOMAIN)) {
    		domain = "Manufacturer";
    	} else if(domain.equalsIgnoreCase(ApplicationInfo.OPERATOR_DOMAIN)) {
    		domain = "Operator";
    	} else if(domain.equalsIgnoreCase(ApplicationInfo.IDENTIFIED_THIRD_PARTY_DOMAIN)) {
    		domain = "IdentifiedThirdParty";
    	} else {
    		domain = "UnidentifiedThirdParty";
    	}
		return domain;
	}
    
    public static String getForcedDomainCategory() {
    	String domain = System.getProperty("forcedomain");
    	if(domain == null) {
    		domain = ApplicationInfo.UNIDENTIFIED_THIRD_PARTY_DOMAIN;
    	} else if(domain.equalsIgnoreCase("MFD")) {
    		domain = ApplicationInfo.MANUFACTURER_DOMAIN;
    	} else if(domain.equalsIgnoreCase("OPD")) {
    		domain = ApplicationInfo.OPERATOR_DOMAIN;
    	} else if(domain.equalsIgnoreCase("ITPD")) {
    		domain = ApplicationInfo.IDENTIFIED_THIRD_PARTY_DOMAIN;
    	} else {
    		domain = ApplicationInfo.UNIDENTIFIED_THIRD_PARTY_DOMAIN;
    	}
		return domain;
	}

    /*
     * Hashtable containing the all of the authentication credentials
     * of different aplications being installed
     */
    private Hashtable iAuthCredentials;

    /*
     * Hashtable containing the selected authentication credentials of
     * different aplications being installed
     */
    private Hashtable iSelectedAuthCredentials;

    /*
     * Hashtable containing the ocsp checkers corresponding to
     * installation of various MIDlet suites
     */
    private Hashtable iOcspCheckers;

    /*
     * Hashtable containing the ocsp event listeners corresponding to
     * ocsp checks of various MIDlet suites
     */
    private Hashtable iOcspEventListeners;

    // self
    private static AuthenticationModule self;

    // data structure which holds the flags about different suites
    // being legacy suites or not; the flag info is available at
    // authentication JAD operation time, but not available at
    // authentication JAR operation time -> this hashtable carries
    // the flag between authenticating JAD and JAR operations for
    // same suite
    private static Hashtable iLegacySuiteFlags = new Hashtable();

    /**
     * The ocsp settings
     */
    private static OcspSettings iOcspSettings;
    private static OcspUserPreferences iOcspUserPreferences;

    /*
     * The security warnings mode
     */
    private static int iSecurityWarningsMode = 2;

    /**
     * Creates an instance of the AuthenticationModule
     *
     * @return An instance of AuthenticationModule
     */
    public static AuthenticationModule getInstance()
    {
        if (self == null)
        {
            self = new AuthenticationModule();
        }
        return self;
    }

    /**
     * Authenticates a certain MIDlet suite. This method is called
     * when/if the JAD is available
     *
     * @param msUID    the UID if the MIDlet suite being authenticated
     * @param oldMSUID the UID if the MIDlet suite being updated
     *                 (if applicable)
     * @param authInfo the authentication info based on which the MIDlet suite
     *                 is authenticated
     * @return         a set of credentials assigned to the MIDlet suite
     */
    public AuthenticationCredentials[] authenticateJad(
        Uid msUID,
        Uid oldMSUID,
        AuthenticationInfo[] authInfo)
    {
        Vector allAuthCredentials = null;
            // this is untrusted MIDlet -> save the protection domain only
            allAuthCredentials = verifyUpdate(
                                     new Credentials[] {new Credentials(getForcedDomainName(),
                                    		 getForcedDomainCategory(),
                                                                        null, null, -1, null)
                                                       }, oldMSUID);
        
        iAuthCredentials.put(msUID, allAuthCredentials);
        Credentials[] credentials = new Credentials[allAuthCredentials.size()];
        allAuthCredentials.copyInto(credentials);
        Logger.logAuthenticationCredentials(allAuthCredentials);
        return credentials;
    }

	/**
     * Authenticates a certain MIDlet suite. This method is called
     * when the JAR is available
     *
     * @param storageSession the JavaStorage session to be used when
     *                       storing security data
     * @param msUID          the UID if the MIDlet suite being authenticated
     * @param oldMSUID       the UID if the MIDlet suite being updated
     *                       (if applicable)
     * @param appJARPath     the path to the JAR being authenticated
     */
    public AuthenticationCredentials[] authenticateJar(
        Uid msUID,
        Uid oldMSUID,
        String appJARPath,
        boolean drmContent)
    {
        AuthenticationStorageData data = null;
        Credentials selectedCredentials = null;
        try
        {
           // Vector allAuthCredentials = (Vector)iAuthCredentials.get(msUID);
            String jarHash = null;
            try
            {
                jarHash = _computeHash(appJARPath);
            }catch(AuthenticationException e) {}
            if (jarHash == null || jarHash.length() == 0)
            {
                // could not compute hash for the given application
                Logger.logWarning("Could not compute hash for " + appJARPath);
                throw new InstallerSecurityException(
                    InstallerErrorMessage.INST_UNEXPECTED_ERR,
                    null, /* no params for short msg */
                    InstallerDetailedErrorMessage.INTERNAL_ERROR,
                    new String[] {"Could not compute hash for " + appJARPath},
                    OtaStatusCode.INTERNAL_ERROR);
            }
                data = new AuthenticationStorageData(
                    getForcedDomainName(),
                    getForcedDomainCategory(),
                    jarHash,
                    null /*rootHashValue*/,
                    null /*validatedChainIndexes*/,
                    null /* jarPath*/,
                    iSecurityWarningsMode);
                selectedCredentials = new Credentials(
                    data.getProtectionDomain(),
                    data.getProtectionDomainCategory(),
                    jarHash,
                    null /* root hash */,
                    -1 /* validated chain index*/,
                    null /* signing cert */);
                verifyUpdate(
                    new Credentials[] {selectedCredentials},
                    oldMSUID);
            
               
        }
        finally
        {
            // remove all the auth credentials with the selection
            if (data != null)
            {
                iSelectedAuthCredentials.put(msUID, data);
            }
        }
        return new AuthenticationCredentials[] {selectedCredentials};
    }

    /**
     */
    public AuthenticationCredentials[] authenticateJar(
        Uid uid,
        Uid oldUid,
        ProtectionDomain protectionDomain,
        String appJARPath)
    {
        Credentials selectedCredentials = null;
        if (protectionDomain == null
                || (!protectionDomain.equals(ProtectionDomain.getManufacturerDomain())
                    && !protectionDomain.equals(ProtectionDomain.getOperatorDomain())
                    && !protectionDomain.equals(ProtectionDomain.getIdentifiedThirdPartyDomain())
                    && !protectionDomain.equals(ProtectionDomain.getUnidentifiedThirdPartyDomain())))
        {
            Logger.logWarning("Unknown protection domain " + protectionDomain);
            throw new InstallerSecurityException(
                InstallerErrorMessage.INST_UNEXPECTED_ERR,
                null, /* no params for short msg */
                InstallerDetailedErrorMessage.INTERNAL_ERROR,
                new String[] {"Unknown protection domain " + protectionDomain},
                OtaStatusCode.INTERNAL_ERROR);
        }
        String jarHash = null;
        try
        {
            jarHash = _computeHash(appJARPath);
        }catch(AuthenticationException e) {}
        if (jarHash == null || jarHash.length() == 0)
        {
            // could not compute hash for the given application
            Logger.logWarning("Could not compute hash for " + appJARPath);
            throw new InstallerSecurityException(
                InstallerErrorMessage.INST_UNEXPECTED_ERR,
                null, /* no params for short msg */
                InstallerDetailedErrorMessage.INTERNAL_ERROR,
                new String[] {"Could not compute hash for " + appJARPath},
                OtaStatusCode.INTERNAL_ERROR);
        }
        AuthenticationStorageData data = new AuthenticationStorageData(
            protectionDomain.getName(),
            protectionDomain.getCategory(),
            jarHash,
            null /*rootHashValue*/,
            null /*validatedChainIndexes*/,
            null /* jarPath*/,
            iSecurityWarningsMode);
        selectedCredentials = new Credentials(
            data.getProtectionDomain(),
            data.getProtectionDomainCategory(),
            jarHash,
            null /* root hash */,
            -1 /* validated chain index*/,
            null /* signing cert */);
        verifyUpdate(
            new Credentials[] {selectedCredentials},
            oldUid);

        iSelectedAuthCredentials.put(uid, data);

        return new AuthenticationCredentials[] {selectedCredentials};
    }

    /**
     * Registers a listener for ocsp events corresponding to the
     * installation of a certain MIDlet suite
     *
     * @param aMsUid    the uid of the MIDlet suite on behalf
     *                  of which the listener is registered
     * @param aListener the ocsp events listener
     */
    public void registerOcspEventListener(Uid aMsUid,
                                          OcspEventListener aListener)
    {
        if (aMsUid != null && aListener != null)
        {
            Logger.log("OcspEventListener registered on behalf of the suite " + aMsUid.toString());
            iOcspEventListeners.put(aMsUid, aListener);
        }
    }

    /**
     * Unregisters the listener for ocsp events corresponding to the
     * installation of a certain MIDlet suite
     *
     * @param aMsUid    the uid of the MIDlet suite on behalf
     *                  of which the listener is unregistered
     */
    public void unregisterOcspEventListener(Uid aMsUid)
    {
        if (aMsUid != null)
        {
            Logger.log("OcspEventListener unregistered on behalf of the suite " + aMsUid.toString());
            iOcspEventListeners.remove(aMsUid);
        }
    }

    /**
     * Cancels any Ocsp checks (if any)
     *
     * @param msUid the UID if the MIDlet suite oh whose behalf the ocsp
     *              checks are canceled
     */
    public void cancelOcspCheck(Uid msUid)
    {
        OcspChecker ocspChecker = (OcspChecker)iOcspCheckers.get(msUid);
        if (ocspChecker != null)
        {
            ocspChecker.cancel();
        }
    }

    /**
     * Returns the signing info of certain application suite
     *
     * @param aAppSuiteName    the name of the application suite for which the
                               signing info is queried
     * @param aAppSuiteVersion the version of the application suite for which
     *                         the signing info is queried
     * @param aAppSuiteVendor  the vendor of the application suite for which
                               the signing info is queried
     * @return                 The signing info if the queried application
     *                         suite has been signed or NULL otherwise
     */
    public SigningInfo getSigningInfo(String aAppSuiteName,
                                      String aAppSuiteVersion,
                                      String aAppSuiteVendor)
    {
        SecurityStorage storage = new SecurityStorage();
        try
        {
            AuthenticationStorageData authData = storage.
                                                 readAuthenticationStorageData(
                                                     aAppSuiteName, aAppSuiteVersion, aAppSuiteVendor,
                                                     SecurityStorage.AUTHENTICATION_DOMAIN_NAME_QUERY
                                                     | SecurityStorage.AUTHENTICATION_DOMAIN_CATEGORY_QUERY
                                                     | SecurityStorage.AUTHENTICATION_ROOT_HASH_QUERY);
            if (authData != null)
            {
                Certificate signingCert = null;
                Certificate rootCert = null;
                AppAccessAuthorizationStorageData appAccesAuthData = storage
                        .readAppAccessAuthorizationStorageData(aAppSuiteName,
                                                               aAppSuiteVersion, aAppSuiteVendor,
                                                               SecurityStorage.APP_ACCESS_AUTH_SIGNERS_LIST_QUERY);
                if (appAccesAuthData != null && appAccesAuthData.getSignersList() != null
                        && appAccesAuthData.getSignersList().length > 0)
                {
                    signingCert = _parseCertificate(
                                      appAccesAuthData.getSignersList()[0]);
                    rootCert = _getRootCertificate(
                                   authData.getRootHashValue());
                }
                return new SigningInfo(signingCert, rootCert,
                                       new ProtectionDomain(authData.getProtectionDomain(),
                                                            authData.getProtectionDomainCategory()));
            }
            return null;
        }
        finally
        {
            storage.close();
        }
    }


    /**
     * Removes all the security data related to a certain MIDlet suite
     *
     * @param sessionID the JavaStorage session to be used when
     *                  removing the security data
     * @param msUID     the UID if the MIDlet suite whose security data is
     *                  being removed
     */
    public void removeSecurityData(StorageSession storageSession, Uid msUID)
    {
        Logger.log("Remove authentication data");
        SecurityStorage storage = new SecurityStorage(storageSession);
        storage.removeAuthenticationStorageData(msUID);
        // clean the caches as well
        iAuthCredentials.remove(msUID);
        iSelectedAuthCredentials.remove(msUID);
        iLegacySuiteFlags.remove(msUID);
        OcspChecker ocspChecker = (OcspChecker)iOcspCheckers.remove(msUID);
        if (ocspChecker != null)
        {
            ocspChecker.destroy();
        }
        iOcspEventListeners.remove(msUID);
    }

    /**
     * Writes to storage all the security data related to a certain MIDlet suite
     *
     * @param sessionID the JavaStorage session to be used when
     *                  writing the security data into storage
     * @param msUID     the UID if the MIDlet suite whose security data is
     *                  being written
     */
    public void addSecurityData(StorageSession storageSession, Uid msUID, Uid oldMsUID)
    {
        Logger.log("Write authentication data to storage");
        AuthenticationStorageData authStorageData =
            (AuthenticationStorageData)iSelectedAuthCredentials.remove(
                msUID);
        writeAuthenticationStorageData(storageSession, msUID, authStorageData,
            (oldMsUID != null && oldMsUID.equals(msUID)));
    }

    /**
     * Returns the details of the certificates used for authenticating a
     * MIDlet suite. This method is used at installation time.
     *
     * @param sessionID the JavaStorage session to be used when
     *                  retrieving the certificates details
     * @param msUID     the UID if the MIDlet suite whose certificate details
     *                  are queried
     * @return          the details of the certificate used for authenticating
     *                  the MIDlet suite or null if the details are not
     *                  available
     */
    public SigningCertificate[] getCertificatesDetails(StorageSession storageSession, Uid msUID)
    {
        Vector allAuthCredentials = (Vector)iAuthCredentials.get(msUID);
        SigningCertificate[] certDetails = null;
        if (allAuthCredentials != null && allAuthCredentials.size() > 0)
        {
            Vector vCertDetails = new Vector();
            for (int i=0; i<allAuthCredentials.size(); i++)
            {
                Credentials credentials = ((Credentials)allAuthCredentials
                                           .elementAt(i));
                Certificate cert = credentials.signingCert;
                if (cert != null)
                {
                    vCertDetails.addElement(new SigningCertificate(
                                                cert, credentials.rootHashValue,
                                                credentials.getProtectionDomainName(),
                                                credentials.getProtectionDomainCategory()));
                }
            }
            if (vCertDetails.size() > 0)
            {
                certDetails = new SigningCertificate[vCertDetails.size()];
                vCertDetails.copyInto(certDetails);
            }
        }
        else
        {
            // if cert details are not found in cache, retrieve the signing
            // certificate from storage and extract the details from it
            SecurityStorage storage = new SecurityStorage(storageSession);
            SigningCertificate signingCertificate = retrieveSigningCertificate(
                                                        storage, msUID);
            if (signingCertificate != null)
            {
                certDetails = new SigningCertificate[1];
                certDetails[0] = signingCertificate;
            }
        }
        return certDetails;
    }

    /**
     * Returns the protection domain info of a certain MIDlet suite. This
     * method is used at uninstallation time.
     *
     * @param sessionID the JavaStorage session to be used when
     *                  retrieving the domain category
     * @param msUID     the UID if the MIDlet suite whose protection
     *                  domain info is queried
     * @param           one of the constants defined in ApplicationInfo
     */
    public String getProtectionDomainCategory(StorageSession storageSession, Uid msUID)
    {
        SecurityStorage storage = new SecurityStorage(storageSession);
        return storage.readProtectionDomainCategory(msUID);
    }

    /**
     * Notification about the media where a certain MIDlet suite is installed.
     *
     * @param aStorageSession the JavaStorage session to be used when/if
     *                        making storage operations related to this
     *                        notification
     * @param aMsUid          the UID of the MIDlet suite whose media info is
     *                        notified
     * @param aMediaId        the identifier of the media where the MIDlet
     *                        suite is installed
     */
    public void setMediaId(Uid aMsUid, int aMediaId)
    {
        // store the jar hash only if the suite was installed on a non-protected media
        if (isDriveProtected(aMediaId))
        {
            AuthenticationStorageData authStorageData =
                (AuthenticationStorageData)iSelectedAuthCredentials.get(
                    aMsUid);
            if (authStorageData != null)
            {
                Logger.log("Suite installed on protected media -> the runtime tamper detection is disabled");
                authStorageData.setJarHashValue(null);
                iSelectedAuthCredentials.put(aMsUid, authStorageData);
            }
        }
    }

    /**
     * Setter for the OCSP settings
     */
    public void setOCSPFlags(OcspSettings ocspSettings)
    {
        Logger.log("Ocsp settings = " + ocspSettings.toString());
        iOcspSettings = ocspSettings;
    }

    /**
     * Performs a cleanup (e.g. on cached data)
     *
     */
    public void cleanup()
    {
        Logger.log("Cleanup authentication module cache");
        iAuthCredentials.clear();
        iSelectedAuthCredentials.clear();
        iLegacySuiteFlags.clear();
        iOcspCheckers.clear();
        iOcspEventListeners.clear();
    }

    /**
     * Verifies the authenticity of MIDlet suites
     *
     * @param msUid           The Uid of the MIDlet suite whose authenticity
     *                        is verified
     * @param authStorageData The stored authentication data assigned to the
     *                        MIDlet suite whose authenticity is verified
     *
     */
    public void verifyMIDletSuiteAuthenticity(Uid msUid, AuthenticationStorageData authStorageData)
    {
        Logger.log("Verifying the authenticity of the suite " + msUid.toString());
        // for the operator MIDlets, check if there are any network restrictions
        if (ApplicationInfo.OPERATOR_DOMAIN.equals(
                    authStorageData.getProtectionDomainCategory()))
        {
            Logger.log("  Checking network restrictions for operator signed suites");
            // get the restrictions from storage
            SecurityStorage storage = new SecurityStorage();
            String networkRestrictions = storage.readNetworkRestrictions(msUid);
            storage.close();
            if (networkRestrictions != null
                    && networkRestrictions.length() > 0)
            {
                // get the real network codes
                TelUtils.NetworkCodes networkCodes = TelUtils.getNetworkCodes();
                boolean found = false;
                if (networkCodes != null)
                {
                    Logger.log("    Network restrictions: " + networkRestrictions);
                    Logger.log("    Network codes: mcc(" + networkCodes.mcc + ") mnc(" + networkCodes.mnc + ")");
                    // go through the list of restrictions and try to find a match
                    // the list of restrictions is a space-separated list of MCC-MNC*/
                    String[] tuples = Tokenizer.split(networkRestrictions, " ");
                    if (tuples != null)
                    {
                        for (int i=0; i<tuples.length; i++)
                        {
                            int mccEndPos = tuples[i].indexOf('-');
                            String mcc = tuples[i].substring(0, mccEndPos);
                            String mnc = tuples[i].substring(mccEndPos + 1);
                            if (mcc.equals(networkCodes.mcc)
                                    && mnc.equals(networkCodes.mnc))
                            {
                                found = true;
                                break;
                            }
                        }
                    }
                }
                if (!found)
                {
                    Logger.logWarning("  -> the network restrictions are violated");
                    throw new RuntimeSecurityException(
                        SecurityErrorMessage.NETWORK_RESTRICTION_VIOLATION,
                        null, /* no params for short msg */
                        SecurityDetailedErrorMessage.NETWORK_RESTRICTION_VIOLATION,
                        null /* no params for detailed msg */);
                }
                Logger.log("  -> the network restrictions are obeyed");
            }
        }

        // check the root validity (if applicable)
        if (authStorageData.getRootHashValue() != null
                && authStorageData.getRootHashValue().length() > 0)
        {
            Logger.log("  Checking validity of the root certificate used in authentication");
            switch (retrieveRootState(authStorageData.getRootHashValue()))
            {
            case SecurityCommsMessages.JAVA_CERT_STORE_STATE_ENABLED:
                // ok -> just go on
                Logger.log("    Root ok");
                break;
            case SecurityCommsMessages.JAVA_CERT_STORE_STATE_DISABLED:
                Logger.logWarning("    Root disabled");
                throw new RuntimeSecurityException(
                    SecurityErrorMessage.CERT_NOT_AVAILABLE,
                    null, /* no params for short msg */
                    SecurityDetailedErrorMessage.CERT_DISABLED,
                    null /* no params for detailed msg */);
            case SecurityCommsMessages.JAVA_CERT_STORE_STATE_DELETED:
                Logger.logWarning("    Root deleted");
                throw new RuntimeSecurityException(
                    SecurityErrorMessage.CERT_NOT_AVAILABLE,
                    null, /* no params for short msg */
                    SecurityDetailedErrorMessage.CERT_DELETED,
                    null /* no params for detailed msg */);
            case SecurityCommsMessages.JAVA_CERT_STORE_STATE_NOT_PRESENT:
                Logger.logWarning("    Root not available");
                throw new RuntimeSecurityException(
                    SecurityErrorMessage.CERT_NOT_AVAILABLE,
                    null, /* no params for short msg */
                    SecurityDetailedErrorMessage.SIM_CHANGED,
                    null /* no params for detailed msg */);
            case SecurityCommsMessages.JAVA_CERT_STORE_STATE_UNKNOWN:
                Logger.logWarning("    Root unknown");
                throw new RuntimeSecurityException(
                    SecurityErrorMessage.CERT_NOT_AVAILABLE,
                    null, /* no params for short msg */
                    SecurityDetailedErrorMessage.UNIDENTIFIED_APPLICATION,
                    null /* no params for detailed msg */);
            }
        }

        if (authStorageData.getJarPath() == null
                || authStorageData.getJarPath().length() == 0)
        {
            Logger.logWarning("  JarPath not available");
            throw new RuntimeSecurityException(
                SecurityErrorMessage.UNEXPECTED_ERR,
                null, /* no params for short msg */
                SecurityDetailedErrorMessage.UNIDENTIFIED_APPLICATION,
                null /* no params for detailed msg */);
        }

        // do the tamper detection
        if (authStorageData.getJarHashValue() != null
                && authStorageData.getJarHashValue().length() > 0)
        {
            Logger.log("  Doing tamper detection");
            String computedJarHash = null;
            try
            {
                computedJarHash = _computeHash(authStorageData.getJarPath());
            }catch(AuthenticationException e)
            {
                if (e.getErrorCode()
                    == AuthenticationException.JAR_NOT_FOUND)
                {
                    Logger.logWarning("    Jar not found while trying to compute hash");
                    throw new RuntimeSecurityException(
                        SecurityErrorMessage.JAR_NOT_FOUND,
                        null, /* no params for short msg */
                        SecurityDetailedErrorMessage.JAR_NOT_FOUND,
                        null /* no params for detailed msg */);
                }
            }
            // do the tampering check: compute the hash and compare it with the stored hash
            if (computedJarHash == null || !computedJarHash.equals(
                        authStorageData.getJarHashValue()))
            {
                Logger.logWarning("    Application has been tampered");
                throw new RuntimeSecurityException(
                    SecurityErrorMessage.JAR_TAMPERED,
                    null, /* no params for short msg */
                    SecurityDetailedErrorMessage.JAR_TAMPERED,
                    null /* no params for detailed msg */);
            }
        }
    }

    private AuthenticationModule()
    {
        iAuthCredentials = new Hashtable();
        iSelectedAuthCredentials = new Hashtable();
        iOcspCheckers = new Hashtable();
        iOcspEventListeners = new Hashtable();
        // default ocsp settings
        iOcspSettings = new OcspSettings(
            OcspSettings.OCSP_MODE_UNDEFINED,
            OcspSettings.OCSP_WARNING_UNDEFINED,
            false /* silent*/,
            "0" /* iap */,
            "0" /* snap */);
        iOcspUserPreferences = new OcspUserPreferences();
        iSecurityWarningsMode = 2;
        Logger.log("Ocsp user preferences = " + iOcspUserPreferences.toString());
    }

    private SigningCertificate retrieveSigningCertificate(SecurityStorage storage, Uid msUID)
    {
        SigningCertificate signingCertificate = null;
        AppAccessAuthorizationStorageData authData = storage
                .readAppAccessAuthorizationStorageData(msUID,
                                                       SecurityStorage.APP_ACCESS_AUTH_SIGNERS_LIST_QUERY);
        if (authData != null && authData.getSignersList() != null
                && authData.getSignersList().length > 0)
        {
            Certificate cert = _parseCertificate(authData
                                                 .getSignersList()[0]);
            if (cert != null)
            {
                AuthenticationStorageData signingData = storage.
                                                        readAuthenticationStorageData(msUID);
                signingCertificate = new SigningCertificate(cert,
                        signingData.getRootHashValue(),
                        signingData.getProtectionDomain(),
                        signingData.getProtectionDomainCategory());
            }
        }
        return signingCertificate;
    }

    private Vector verifyUpdate(Credentials[] credentials, Uid oldMSUID)
    {
        return verifyUpdate(isLegacySuite(oldMSUID), credentials, oldMSUID, false /* don't order the returned credentials */);
    }

    // Security rules for update:
    // 1. the old and the new MIDlet suites must be bound to the same
    // protection domain
    // 2. Only for MIDP3 MIDlets, the the old and the new MIDlet
    // suites MUST share at least one common signer (for legacy MIDlets
    // it is ok not to share a common signer, case in which the update
    // is decided by the user)
    //
    // Common signer is defined as matching the Organization field
    // within the Subject field of the signing certificate of MIDlet
    // Suite update and the signing certificate of the original MIDlet
    // Suite, where the signing certificates are validated against
    // the same Protection Domain Root Certificate)
    //
    // This method discards the credentials which do not obey the rules
    // mentioned above and returns either all credentials which have same
    // signer OR all credentials which do NOT have same signer,
    // but not any combination
    private Vector verifyUpdate(boolean legacyMIDletSuite, Credentials[] credentials, Uid oldMSUID, boolean orderResult)
    {
        Vector allCredentials = new Vector(credentials.length);
        for (int i=0; i<credentials.length; i++)
        {
            allCredentials.addElement(credentials[i]);
        }
        if (oldMSUID != null)
        {
            SecurityStorage storage = new SecurityStorage();
            Vector sameSignerCredentials = new Vector();
            Vector differentSignerCredentials = new Vector();
            try
            {
                ProtectionDomain oldProtectionDomain = new ProtectionDomain(
                    storage.readProtectionDomain(oldMSUID),
                    storage.readProtectionDomainCategory(oldMSUID));
                for (int i=0; i<credentials.length; i++)
                {
                    if (oldProtectionDomain.equals(
                                credentials[i].getProtectionDomain()))
                    {
                        SigningCertificate oldSigningCertificate =
                            retrieveSigningCertificate(storage, oldMSUID);
                        SigningCertificate newSigningCertificate =
                            new SigningCertificate(credentials[i].signingCert,
                                                   credentials[i].rootHashValue,
                                                   credentials[i].getProtectionDomainName(),
                                                   credentials[i].getProtectionDomainCategory());
                        if (newSigningCertificate.isSameSigner(
                                    oldSigningCertificate))
                        {
                            sameSignerCredentials.addElement(credentials[i]);
                        }
                        else if (legacyMIDletSuite)
                        {
                            differentSignerCredentials.addElement(credentials[i]);
                        }
                    }
                    else if (legacyMIDletSuite
                             && !ApplicationInfo.UNIDENTIFIED_THIRD_PARTY_DOMAIN.equals(
                                 credentials[i].getProtectionDomain().getCategory()))
                    {
                        differentSignerCredentials.addElement(credentials[i]);
                    }
                }
                if (sameSignerCredentials.size() != 0)
                {
                    allCredentials = sameSignerCredentials;
                }
                else if (differentSignerCredentials.size() != 0)
                {
                    allCredentials = differentSignerCredentials;
                }
            }
            finally
            {
                storage.close();
            }
        }
        if (orderResult)
        {
            // put the credentials with domain info first
            int i=0;
            int size = allCredentials.size();
            while (i<size)
            {
                Credentials current = (Credentials)allCredentials.elementAt(i);
                if (current.getProtectionDomainName() == null
                        || current.getProtectionDomainCategory() == null)
                {
                    // swap the current element with the last one
                    Object last = allCredentials.lastElement();
                    allCredentials.setElementAt(last,i);
                    allCredentials.setElementAt(current,(size-1));
                    size--;
                }
                else
                {
                    i++;
                }
            }
        }
        return allCredentials;
    }

    private boolean isLegacySuite(Uid msUID)
    {
        if (msUID == null)
        {
            return true;
        }
        Boolean tmp = (Boolean)iLegacySuiteFlags.remove(msUID);
        if (tmp != null)
        {
            return tmp.booleanValue();
        }
        else
        {
            SecurityStorage storage = new SecurityStorage();
            String suiteVersion = storage.readSuiteVersion(msUID);
            storage.close();
            if (suiteVersion != null)
            {
                boolean legacySuite = !suiteVersion.equalsIgnoreCase(
                                          SecurityAttributes.MIDP3_VERSION_ATTRIBUTE_VALUE);
                iLegacySuiteFlags.put(msUID, new Boolean(legacySuite));
                return legacySuite;
            }
            return true;
        }
    }

    private String getRoot(String rootHash)
    {
        CommsEndpoint comms = null;
        try
        {
            comms = new CommsEndpoint();
            comms.connect(CommsEndpoint.JAVA_CAPTAIN);
            CommsMessage sMessage = new CommsMessage();
            sMessage.setMessageId(SecurityCommsMessages.JAVA_CERT_STORE_MSG_ID_REQUEST);
            sMessage.setModuleId(SecurityCommsMessages.PLUGIN_ID_JAVA_CERT_STORE_EXTENSION);
            sMessage.write(SecurityCommsMessages.JAVA_CERT_STORE_OPERATION_QUERY_CERTS);
            // add filter
            sMessage.write(SecurityCommsMessages.JAVA_CERT_STORE_FILTER_ID_STATE);
            sMessage.write(SecurityCommsMessages.JAVA_CERT_STORE_STATE_ENABLED);
            sMessage.write(SecurityCommsMessages.JAVA_CERT_STORE_FILTER_ID_HASH);
            sMessage.write(rootHash);
            // add the query ID
            sMessage.write(SecurityCommsMessages.JAVA_CERT_STORE_QUERY_ID_CERT_CONTENT_PEM);
            CommsMessage rMessage = comms.sendReceive(sMessage, 10);
            // read the reply
            String tmp = rMessage.readString();
            if (tmp != null && tmp.length() > 0)
            {
                return rMessage.readString();
            }
        }
        catch (CommsException e)
        {
            // fall through
        }
        finally
        {
            if (comms != null)
            {
                comms.destroy();
            }
        }
        return null;
    }

    private int retrieveRootState(String rootHash)
    {

        CommsEndpoint comms = null;
        try
        {
            comms = new CommsEndpoint();
            comms.connect(CommsEndpoint.JAVA_CAPTAIN);
            CommsMessage sMessage = new CommsMessage();
            sMessage.setMessageId(SecurityCommsMessages.JAVA_CERT_STORE_MSG_ID_REQUEST);
            sMessage.setModuleId(SecurityCommsMessages.PLUGIN_ID_JAVA_CERT_STORE_EXTENSION);
            sMessage.write(SecurityCommsMessages.JAVA_CERT_STORE_OPERATION_QUERY_CERTS);
            // add filter
            sMessage.write(SecurityCommsMessages.JAVA_CERT_STORE_FILTER_ID_HASH);
            sMessage.write(rootHash);
            // add the query ID
            sMessage.write(SecurityCommsMessages.JAVA_CERT_STORE_QUERY_ID_STATE);
            CommsMessage rMessage = comms.sendReceive(sMessage, 10);
            // read the reply
            return rMessage.readInt();
        }
        catch (CommsException e)
        {
            // fall through
        }
        finally
        {
            if (comms != null)
            {
                comms.destroy();
            }
        }
        return SecurityCommsMessages.JAVA_CERT_STORE_STATE_UNKNOWN;
    }

    private boolean performOcsp()
    {
        if (iOcspSettings.ocspMode
                != OcspSettings.OCSP_MODE_UNDEFINED)
        {
            return (iOcspSettings.ocspMode == OcspSettings.OCSP_MODE_ENABLED);
        }
        // check the user preferences
        return (iOcspUserPreferences.getOcspMode()
                == OcspUserPreferences.OCSP_MODE_ON
                || iOcspUserPreferences.getOcspMode()
                == OcspUserPreferences.OCSP_MODE_MUST);
    }

    private boolean isDriveProtected(int aMediaId)
    {
        DriveInfo[] allDrives = DriveUtilities.getAllDrives();
        boolean driveFound = false;
        if (allDrives != null)
        {
            for (int i=0; i<allDrives.length; i++)
            {
                if (aMediaId == allDrives[i].iId)
                {
                    if (allDrives[i].iIsRemovable)
                    {
                        return false;
                    }
                    if (allDrives[i].iIsExternallyMountable)
                    {
                        return false;
                    }
                    driveFound = true;
                }
            }
        }
        return driveFound;
    }

    private Credentials selectCredentials(String selectedJarHash, Vector allAuthCredentials, Vector validatedChainIndexes)
    {
        Credentials selectedCredentials = null;
        if (selectedJarHash != null)
        {
            for (int i=0; i<allAuthCredentials.size(); i++)
            {
                Credentials authCredentials =
                    (Credentials)allAuthCredentials.elementAt(i);
                if (selectedJarHash.equalsIgnoreCase(authCredentials.jarHashValue))
                {
                    // the first one wins
                    if (selectedCredentials == null)
                    {
                        selectedCredentials = new Credentials(
                            authCredentials.getProtectionDomainName(),
                            authCredentials.getProtectionDomainCategory(),
                            authCredentials.jarHashValue,
                            authCredentials.rootHashValue,
                            -1,
                            null);
                    }
                    // collect the validated chain indexes
                    validatedChainIndexes.addElement(
                        new Integer(authCredentials.validatedChainIndex));
                }
            }
        }
        return selectedCredentials;
    }

    private void writeAuthenticationStorageData(StorageSession storageSession, Uid uid, AuthenticationStorageData data, boolean isUpdate)
    {
        if (storageSession == null)
        {
            return;
        }
        SecurityStorage storage = new SecurityStorage(storageSession);
        storage.writeAuthenticationStorageData(uid, data, isUpdate);
        Logger.logAuthenticationData(data);
    }

    private native Credentials[] _validateChainsAndSignatures(AuthenticationInfo[] authInfo);
    private native String _computeHash(String appJARPath);
    private native String _drmDecryptAndComputeHash(String appJARPath);
    private native Certificate _parseCertificate(String rawCert);
    private native Certificate _getRootCertificate(String certHash);
}