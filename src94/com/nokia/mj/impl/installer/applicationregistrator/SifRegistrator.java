/*
* Copyright (c) 2008-2010 Nokia Corporation and/or its subsidiary(-ies).
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


package com.nokia.mj.impl.installer.applicationregistrator;

import com.nokia.mj.impl.installer.storagehandler.ApplicationInfo;
import com.nokia.mj.impl.installer.storagehandler.SuiteInfo;
import com.nokia.mj.impl.installer.utils.ComponentId;
import com.nokia.mj.impl.installer.utils.InstallerException;
import com.nokia.mj.impl.installer.utils.FileUtils;
import com.nokia.mj.impl.installer.utils.Log;
import com.nokia.mj.impl.installer.utils.PlatformUid;
import com.nokia.mj.impl.rt.installer.ApplicationInfoImpl;
import com.nokia.mj.impl.security.midp.authentication.AuthenticationModule;
import com.nokia.mj.impl.utils.Attribute;
import com.nokia.mj.impl.utils.Uid;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

/**
 * Registers (and unregisters) Java application to S60 platform's
 * software installation framework (USIF).
 */
public final class SifRegistrator
{
    /** Added application. Used with notifyAppChange() method. */
    public static final int APP_ADDED = 0;
    /** Removed application. Used with notifyAppChange() method. */
    public static final int APP_REMOVED = 1;
    /** Updated application. Used with notifyAppChange() method. */
    public static final int APP_UPDATED = 2;

    /** Native session handle. */
    private int iSessionHandle = 0;

    /*** ----------------------------- PUBLIC ------------------------------ */

    /**
     * Returns greater than zero if application registration to
     * software installation framework is enabled.
     */
    public static int getSifMode()
    {
        return _getUsifMode();
    }

    /**
     * Launches the application view. If launching application view
     * fails this method does not throw exception but produces an
     * error log entry.
     */
    public static void launchAppView()
    {
        int err = _launchAppView();
        if (err < 0)
        {
            Log.logError("Launching AppLib failed with code " + err);
        }
    }

    /**
     * Notifies system about added/updated/removed applications.
     * This method should be called only after the changes have been
     * committed.
     *
     * @param aAppUids application uids
     * @param aAppChange change type: APP_ADDED, APP_UPDATED, or APP_REMOVED
     * @throws InstallerException if notification fails
     */
    public static void notifyAppChange(Uid[] aAppUids, int aAppChange)
    {
        if (aAppUids == null || aAppUids.length == 0)
        {
            return;
        }
        int[] appUids = new int[aAppUids.length];
        for (int i = 0; i < appUids.length; i++)
        {
            appUids[i] = ((PlatformUid)aAppUids[i]).getIntValue();
        }
        int err = _notifyAppChange(appUids, aAppChange);
        if (err < 0)
        {
            InstallerException.internalError(
                "Notifying app changes failed with code " + err);
        }
    }

    /**
     * Get component uid basing on component id.
     * This method can be called before session is created.
     *
     * @param aCid component id
     * @return uid for the component, or null if component is not found
     * @throws InstallerException if an error occurs
     */
    public static Uid getUid(int aCid)
    {
        // Use ComponentId to return int type value from native to java.
        ComponentId id = new ComponentId();
        int err = _getUid(aCid, id);
        if (err < 0)
        {
            InstallerException.internalError(
                "Getting uid for cid " + aCid + " failed with code " + err);
        }
        Uid uid = null;
        if (id.getId() != 0)
        {
            uid = PlatformUid.createUid(id.getId());
        }
        return uid;
    }

    /**
     * Registers or unregisters Java software type to software
     * installation framework.
     *
     * @param aRegister true for registration, false for unregistration
     */
    public static void registerJavaSoftwareType(boolean aRegister)
    {
        String op = (aRegister? "Register": "Unregister");
        int err = _registerJavaSoftwareType(aRegister);
        if (err < 0)
        {
            InstallerException.internalError(
                op + " Java software type failed with code " + err);
        }
        else
        {
            Log.log("SifRegistrator " + op + "ed Java software type");
        }
    }

    /**
     * Starts application registration session.
     * The registrations and unregistrations are done only
     * when commitSession is called.
     * If you want to discard the registrations and unregistrations
     * call rollbackSession.
     * Does nothing if session has already been successfully started
     * from this SifRegistrator instance.
     *
     * @param aTransaction true if also transaction for this session should
     * be opened, false otherwise
     * @throws InstallerException if the session cannot created
     * @see commitSession
     * @see rollbackSession
     */
    public void startSession(boolean aTransaction)
    {
        if (0 != iSessionHandle)
        {
            // Session has already been created, do nothing.
            Log.logWarning("SifRegistrator.startSession called although session is already open.");
            return;
        }

        // Native method writes error log and returns
        // negative Symbian error code if it fails.
        int ret = _startSession(aTransaction);
        if (ret < 0)
        {
            InstallerException.internalError(
                "Creating session failed with code " + ret);
        }
        //Log.log("SifRegistrator session started");
        iSessionHandle = ret;
    }

    /**
     * Registers Java application suite to S60 USIF.
     *
     * @param aSuiteInfo Information needed to register the application
     * @param aIsUpdate true in case of an update, false in case of a new
     * installation
     * @throws InstallerException if registration cannot done or
     *  startSession has not been called successfully
     * @see startSession
     * @see SuiteInfo
     */
    public void registerSuite(SuiteInfo aSuiteInfo, boolean aIsUpdate)
    {
        if (0 == iSessionHandle)
        {
            InstallerException.internalError("No valid SIF session.");
        }
        Log.log("SifRegistrator registering application suite " +
                aSuiteInfo.getGlobalId());

        if (_getUsifMode() > 0)
        {
            // USIF Phase 2 registration.
            // Register suite as a component.
            registerComponent(aSuiteInfo, aIsUpdate);
            registerLocalizedComponentName(aSuiteInfo, -1);
            // Register applications within the component.
            Vector apps = aSuiteInfo.getApplications();
            for (int i = 0; i < apps.size(); i++)
            {
                registerApplication(aSuiteInfo, i);
            }
        }
        else
        {
            // USIF Phase 1 registration.
            // Register each application in the suite.
            Vector apps = aSuiteInfo.getApplications();
            for (int i = 0; i < apps.size(); i++)
            {
                registerComponent(aSuiteInfo, i, aIsUpdate);
                registerLocalizedComponentName(aSuiteInfo, i);
            }
        }
        registerLocalizedProperties(aSuiteInfo);
    }

    /**
     * Unregisters Java application suite from S60 USIF.
     *
     * @param aSuiteInfo Information needed to unregister the application,
     * @throws InstallerException if unregistration cannot done or
     *  startSession has not been called successfully
     * @see startSession
     * @see SuiteInfo
     */
    public void unregisterSuite(SuiteInfo aSuiteInfo)
    {
        if (0 == iSessionHandle)
        {
            InstallerException.internalError("No valid SIF session.");
        }
        Log.log("SifRegistrator unregistering application suite " +
                aSuiteInfo.getGlobalId());

        if (_getUsifMode() > 0)
        {
            // USIF Phase 2 unregistration.
            // Unregister suite as a component.
            unregisterComponent(aSuiteInfo);
        }
        else
        {
            // USIF Phase 1 unregistration.
            // Unregister each application in the suite.
            Vector apps = aSuiteInfo.getApplications();
            for (int i = 0; i < apps.size(); i++)
            {
                unregisterComponent(aSuiteInfo, i);
            }
        }
    }

    /**
     * Commits the registrations and unregistrations.
     * Ends the current session if commit is successfull.
     * If commit fails the session is kept open so that
     * rollbackSession can be called.
     *
     * @throws InstallerException if session cannot be committed
     */
    public void commitSession()
    {
        if (0 == iSessionHandle)
        {
            InstallerException.internalError("No valid SIF session.");
        }

        int err = _commitSession(iSessionHandle);
        if (err < 0)
        {
            InstallerException.internalError("Commiting session failed with code " + err);
        }
        // Current session has been closed
        iSessionHandle = 0;
        //Log.log("SifRegistrator session committed");
    }

    /**
     * Rolls back the registrations and unregistrations.
     * Ends the current session.
     *
     * @throws InstallerException if session cannot be rolled back.
     */
    public void rollbackSession()
    {
        if (0 == iSessionHandle)
        {
            InstallerException.internalError("No valid SIF session.");
        }

        int err = _rollbackSession(iSessionHandle);
        // Session is closed always when rollback is called
        iSessionHandle = 0;
        if (err < 0)
        {
            InstallerException.internalError("Rolling back the session failed with code " + err);
        }
        //Log.log("SifRegistrator session rolled back");
    }

    /**
     * Closes the current session if it still open.
     * If registerComponent or unregisterComponent has been called,
     * commitSession or rollbackSession must be called instead of this method.
     */
    public void closeSession()
    {
        if (0 == iSessionHandle)
        {
            return;
        }

        _closeSession(iSessionHandle);
        // Current session has been closed
        iSessionHandle = 0;
        //Log.log("SifRegistrator session closed");
    }

    /**
     * Returns the component id of the application.
     *
     * @param aGlobalId the global id for the application.
     * @return the component id for the application, or null if the
     * application with given global id cannot be found.
     * @throws InstallerException if an error occurs
     */
    public ComponentId getComponentId(String aGlobalId)
    {
        if (0 == iSessionHandle)
        {
            InstallerException.internalError("No valid SIF session.");
        }

        ComponentId result = new ComponentId();
        int ret = _getComponentId(iSessionHandle, aGlobalId, result);
        if (-1 == ret)
        {
            // Symbian error code KErrNotFound means that the
            // application with given global id does not exist.
            result = null;
        }
        else if (ret < -1)
        {
            InstallerException.internalError(
                "Getting component id for global id " + aGlobalId +
                " failed with code " + ret);
        }
        return result;
    }

    /**
     * Returns the component id of the application.
     *
     * @param aAppUid the uid for the application.
     * @return the component id for the application, or null if the
     * application with given uid cannot be found.
     * @throws InstallerException if an error occurs
     */
    public ComponentId getComponentId(Uid aAppUid)
    {
        if (0 == iSessionHandle)
        {
            InstallerException.internalError("No valid SIF session.");
        }

        ComponentId result = new ComponentId();
        int ret = _getComponentIdForApp(
                      iSessionHandle, ((PlatformUid)aAppUid).getIntValue(), result);
        if (-1 == ret)
        {
            // Symbian error code KErrNotFound means that the
            // application with given uid does not exist.
            result = null;
        }
        else if (ret < -1)
        {
            InstallerException.internalError(
                "Getting component id for uid " + aAppUid +
                " failed with code " + ret);
        }
        return result;
    }

    /**
     * Writes information of the given application to JavaInstaller log.
     *
     * @param aGlobalId the global id for the application.
     */
    public void logComponent(String aGlobalId)
    {
        if (0 == iSessionHandle)
        {
            InstallerException.internalError("No valid SIF session.");
        }

        int ret = _logComponent(iSessionHandle, aGlobalId);
        if (ret < -1)
        {
            Log.logError("SifRegistrator logComponent failed with code " + ret);
        }
    }

    /*** ----------------------------- PACKAGE ---------------------------- */
    /*** ----------------------------- PRIVATE ---------------------------- */

    /**
     * Registers one Java application to S60 USIF as a component.
     * Used with USIF Phase 1.
     *
     * @param aSuiteInfo Information needed to register the application
     * @param aIndex index of the application in the suite
     * @param aIsUpdate true in case of an update, false in case of a new
     * installation
     * @throws InstallerException if registration cannot done or
     *  startSession has not been called successfully
     * @see startSession
     * @see SuiteInfo
     */
    private void registerComponent(
        SuiteInfo aSuiteInfo, int aIndex, boolean aIsUpdate)
    {
        String globalId = aSuiteInfo.getGlobalId(aIndex);
        if (globalId == null)
        {
            Log.logWarning("SifRegistrator: Application with index " + aIndex +
                           " not found from " + aSuiteInfo.getGlobalId());
            return;
        }
        ApplicationInfo appInfo =
            (ApplicationInfo)aSuiteInfo.getApplications().elementAt(aIndex);
        String suiteName = aSuiteInfo.getName();
        String vendor = aSuiteInfo.getVendor();
        String version = aSuiteInfo.getVersion().toString();
        String name = appInfo.getName();
        int uid = ((PlatformUid)appInfo.getUid()).getIntValue();
        String[] componentFiles = getComponentFiles(aSuiteInfo);
        long componentSize = aSuiteInfo.getInitialSize();
        String attrValue = aSuiteInfo.getAttributeValue("Nokia-MIDlet-Block-Uninstall");
        boolean isRemovable = !(attrValue != null && attrValue.equalsIgnoreCase("true"));
        boolean isDrmProtected = (aSuiteInfo.getContentInfo() == aSuiteInfo.CONTENT_INFO_DRM);
        boolean isOriginVerified = aSuiteInfo.isTrusted();
        String midletInfoUrl = aSuiteInfo.getAttributeValue("MIDlet-Info-URL");
        String midletDescription = aSuiteInfo.getAttributeValue("MIDlet-Description");
        String downloadUrl = aSuiteInfo.getAttributeValue("Nokia-MIDlet-Download-URL");
        ComponentId componentId = new ComponentId();
        int err = _registerComponent(
                      iSessionHandle, uid,
                      getScrString(suiteName), getScrString(vendor),
                      getScrString(version), getScrString(name),
                      getScrString(globalId), componentFiles,
                      componentSize, isRemovable, isDrmProtected,
                      isOriginVerified, aIsUpdate, aSuiteInfo.getMediaId(),
                      getScrString(midletInfoUrl),
                      getScrString(midletDescription),
                      getScrString(downloadUrl),
                      componentId);
        if (err < 0)
        {
            InstallerException.internalError(
                "Registering component " + globalId +
                " failed with code " + err);
        }
        else
        {
            appInfo.setComponentId(componentId);
            Log.log("SifRegistrator registered component " + globalId +
                    " with id " + componentId.getId());
        }
    }

    /**
     * Unregisters one Java application from being S60 USIF component.
     * Used with USIF Phase 1.
     *
     * @param aSuiteInfo Information needed to unregister the application,
     * @param aIndex index of the application in the suite
     * @throws InstallerException if unregistration cannot done or
     *  startSession has not been called successfully
     * @see startSession
     * @see SuiteInfo
     */
    private void unregisterComponent(SuiteInfo aSuiteInfo, int aIndex)
    {
        String globalId = aSuiteInfo.getGlobalId(aIndex);
        if (globalId == null)
        {
            Log.logWarning("SifRegistrator: Application with index " + aIndex +
                           " not found from " + aSuiteInfo.getGlobalId());
            return;
        }
        ComponentId componentId = getComponentId(globalId);
        if (componentId == null)
        {
            Log.logWarning(
                "SifRegistrator unregistration failed, application " +
                globalId + " does not exist");
            return;
        }
        // Save component id to ApplicationInfo.
        ApplicationInfo appInfo =
            (ApplicationInfo)aSuiteInfo.getApplications().elementAt(aIndex);
        appInfo.setComponentId(componentId);
        // Unregister application.
        int err = _unregisterComponent(iSessionHandle, componentId.getId());
        if (err < 0)
        {
            InstallerException.internalError(
                "Unregistering component " + globalId +
                " failed with code " + err);
        }
        else
        {
            Log.log("SifRegistrator unregistered component " + globalId +
                    " with id " + componentId.getId());
        }
    }

    /**
     * Registers Java application suite to S60 USIF as a component.
     * Used with USIF Phase 2.
     *
     * @param aSuiteInfo Suite information
     * @param aIsUpdate true in case of an update, false in case of a new
     * installation
     * @throws InstallerException if registration cannot done or
     *  startSession has not been called successfully
     * @see startSession
     * @see SuiteInfo
     */
    private void registerComponent(SuiteInfo aSuiteInfo, boolean aIsUpdate)
    {
        String globalId = aSuiteInfo.getGlobalId();
        String suiteName = aSuiteInfo.getName();
        String vendor = aSuiteInfo.getVendor();
        String version = aSuiteInfo.getVersion().toString();
        String name = null; // Set name to null so that suite name will be used.
        int uid = ((PlatformUid)aSuiteInfo.getUid()).getIntValue();
        String[] componentFiles = getComponentFiles(aSuiteInfo);
        long componentSize = aSuiteInfo.getInitialSize();
        String attrValue = aSuiteInfo.getAttributeValue("Nokia-MIDlet-Block-Uninstall");
        boolean isRemovable = !(attrValue != null && attrValue.equalsIgnoreCase("true"));
        boolean isDrmProtected = (aSuiteInfo.getContentInfo() == aSuiteInfo.CONTENT_INFO_DRM);
        boolean isOriginVerified = aSuiteInfo.isTrusted();
        String midletInfoUrl = aSuiteInfo.getAttributeValue("MIDlet-Info-URL");
        String midletDescription = aSuiteInfo.getAttributeValue("MIDlet-Description");
        String downloadUrl = aSuiteInfo.getAttributeValue("Nokia-MIDlet-Download-URL");
        ComponentId componentId = new ComponentId();
        int err = _registerComponent(
                      iSessionHandle, uid,
                      getScrString(suiteName), getScrString(vendor),
                      getScrString(version), getScrString(name),
                      getScrString(globalId), componentFiles,
                      componentSize, isRemovable, isDrmProtected,
                      isOriginVerified, aIsUpdate, aSuiteInfo.getMediaId(),
                      getScrString(midletInfoUrl),
                      getScrString(midletDescription),
                      getScrString(downloadUrl),
                      componentId);
        if (err < 0)
        {
            InstallerException.internalError(
                "Registering component " + globalId +
                " failed with code " + err);
        }
        else
        {
            aSuiteInfo.setComponentId(componentId);
            Log.log("SifRegistrator registered component " + globalId +
                    " with id " + componentId.getId());
        }
    }

    /**
     * Unregisters Java application suite from being S60 USIF component.
     * Used with USIF Phase 2.
     *
     * @param aSuiteInfo suite information
     * @throws InstallerException if unregistration cannot done or
     *  startSession has not been called successfully
     * @see startSession
     * @see SuiteInfo
     */
    private void unregisterComponent(SuiteInfo aSuiteInfo)
    {
        String globalId = aSuiteInfo.getGlobalId();
        ComponentId componentId = getComponentId(globalId);
        if (componentId == null)
        {
            Log.logWarning(
                "SifRegistrator unregistration failed, application " +
                globalId + " does not exist");
            return;
        }
        // Save component id to SuiteInfo.
        aSuiteInfo.setComponentId(componentId);
        // Unregister application.
        int err = _unregisterComponent(iSessionHandle, componentId.getId());
        if (err < 0)
        {
            InstallerException.internalError(
                "Unregistering component " + globalId +
                " failed with code " + err);
        }
        else
        {
            Log.log("SifRegistrator unregistered component " + globalId +
                    " with id " + componentId.getId());
        }
    }

    /**
     * Registers one Java application to S60 USIF as an S60 application.
     * The application is registered to component whose id is taken
     * from given SuiteInfo object. The SuiteInfo must already have
     * been registered to USIF as a component with registerComponent()
     * method before this method is called.
     * Used with USIF Phase 2.
     *
     * @param aSuiteInfo information needed to register the application
     * @param aIndex index of the application in the suite
     * @throws InstallerException if registration cannot done or
     *  startSession has not been called successfully
     * @see startSession
     * @see SuiteInfo
     */
    private void registerApplication(SuiteInfo aSuiteInfo, int aIndex)
    {
        int cid = aSuiteInfo.getComponentId().getId();
        ApplicationInfo appInfo =
            (ApplicationInfo)aSuiteInfo.getApplications().elementAt(aIndex);
        int appUid = ((PlatformUid)appInfo.getUid()).getIntValue();
        String appName = appInfo.getName();
        String appFilename = aSuiteInfo.getJarPath();
        String groupName = aSuiteInfo.getInstallationGroup();
        if (groupName == null)
        {
            groupName = ""; // default installation group
        }
        String iconFilename = null;
        if (!appInfo.getUseDefaultIcon())
        {
            iconFilename = aSuiteInfo.getRegisteredIconPath(aIndex);
        }
        Log.log("SifRegistrator iconFilename " + aIndex + ": " + iconFilename);
        int numberOfIcons = 1;
        // Initalize localized names for the application.
        LocalizedName[] localizedNames = getLocalizedNames(
                                             aSuiteInfo, "Nokia-MIDlet-" + (aIndex+1) + "-");
        int[] languages = new int[localizedNames.length];
        String[] appNames = new String[localizedNames.length];
        for (int i = 0; i < localizedNames.length; i++)
        {
            languages[i] = localizedNames[i].getLanguage();
            appNames[i] = localizedNames[i].getName();
        }
        int err = _registerApplication(
                      iSessionHandle, cid, appUid, appName, appFilename, groupName,
                      iconFilename, numberOfIcons, languages, appNames);
        if (err < 0)
        {
            InstallerException.internalError(
                "Registering application " + appUid + " to component " + cid +
                " failed with code " + err);
        }
        else
        {
            Log.log("SifRegistrator registered application " + appUid +
                    " to component " + cid);
        }
    }

    private static String[] getComponentFiles(SuiteInfo aSuite)
    {
        Vector componentFiles = new Vector();
        String path = aSuite.getJadPath();
        if (path != null)
        {
            componentFiles.addElement(getScrString(path));
        }
        path = aSuite.getJarPath();
        if (path != null)
        {
            componentFiles.addElement(getScrString(path));
        }
        boolean addRootPath = true;
        int rootDrive = FileUtils.getDrive(aSuite.getRootDir());
        for (int i = 0; i < componentFiles.size(); i++)
        {
            if (FileUtils.getDrive((String)componentFiles.elementAt(i)) ==
                    rootDrive)
            {
                // File from the root path drive already exists in
                // component files vector, no need to add root path
                // separately.
                addRootPath = false;
                break;
            }
        }
        if (addRootPath)
        {
            componentFiles.addElement(getScrString(aSuite.getRootDir()));
        }
        String[] result = new String[componentFiles.size()];
        componentFiles.copyInto(result);
        return result;
    }

    /**
     * Registers localized names for given application from given suite.
     * This method can be called only after registerComponent method has
     * been called.
     *
     * @param aSuite suite info
     * @param aIndex index of the application within the suite, if -1 then
     * localized names for the suite itself is registered
     */
    private void registerLocalizedComponentName(SuiteInfo aSuite, int aIndex)
    {
        LocalizedName[] localizedNames = null;
        int cid = 0;
        if (aIndex == -1)
        {
            if (aSuite.getComponentId() == null)
            {
                Log.log(
                    "SifRegistrator.registerLocalizedComponentName: cid not present in suite");
                return;
            }
            cid = aSuite.getComponentId().getId();
            localizedNames = getLocalizedNames(aSuite, "Nokia-MIDlet-Name-");
        }
        else
        {
            ApplicationInfo app =
                (ApplicationInfo)aSuite.getApplications().elementAt(aIndex);
            if (app.getComponentId() == null)
            {
                Log.log(
                    "SifRegistrator.registerLocalizedComponentName: cid not present in app");
                return;
            }
            cid = app.getComponentId().getId();
            localizedNames = getLocalizedNames(
                                 aSuite, "Nokia-MIDlet-" + (aIndex+1) + "-");
        }
        for (int i = 0; i < localizedNames.length; i++)
        {
            int err = _registerLocalizedComponentName(
                          iSessionHandle, cid,
                          getScrString(localizedNames[i].getName()),
                          getScrString(aSuite.getVendor()),
                          localizedNames[i].getLanguage());
            if (err < 0)
            {
                InstallerException.internalError(
                    "Adding localized name for component " + cid +
                    " failed with code " + err +
                    " (" + localizedNames[i] + ")");
            }
        }
    }

    /**
     * Registers localized property values for given suite.
     * This method can be called only after registerComponent
     * method has been called.
     *
     * @param aSuite suite info
     */
    private void registerLocalizedProperties(SuiteInfo aSuite)
    {
        if (aSuite.getComponentId() == null)
        {
            Log.log(
                "SifRegistrator.registerLocalizedProperties: cid not present in suite");
            return;
        }
        int cid = aSuite.getComponentId().getId();
        final int UNSPECIFIED_LOCALE = -1; // KUnspecifiedLocale

        // Register MIDlet-Delete-Confirm attribute values.
        final String attrName = "MIDlet-Delete-Confirm";
        String nonlocalizedAttrValue = aSuite.getAttributeValue(attrName);
        int err = _setLocalizedComponentProperty(
                      iSessionHandle, cid, getScrString(attrName),
                      getScrString(nonlocalizedAttrValue), UNSPECIFIED_LOCALE);
        if (err < 0)
        {
            InstallerException.internalError(
                "Adding property " + attrName + " for component " + cid +
                " failed with code " + err + " (" + nonlocalizedAttrValue + ")");
        }
        LocalizedName[] localizedAttrValues =
            getLocalizedNames(aSuite, attrName + "-");
        for (int i = 0; i < localizedAttrValues.length; i++)
        {
            err = _setLocalizedComponentProperty(
                      iSessionHandle, cid, getScrString(attrName),
                      getScrString(localizedAttrValues[i].getName()),
                      localizedAttrValues[i].getLanguage());
            if (err < 0)
            {
                InstallerException.internalError(
                    "Adding localized property " + attrName +
                    " for component " + cid + " failed with code " + err +
                    " (" + localizedAttrValues[i] + ")");
            }
        }

        // Register Domain-Category property.
//        ApplicationInfoImpl appInfoImpl = (ApplicationInfoImpl)
//                                          com.nokia.mj.impl.rt.support.ApplicationInfo.getInstance();
//        String domainCategory = appInfoImpl.getProtectionDomain();
        String domainCategory = AuthenticationModule.getForcedDomainCategory();
        err = _setLocalizedComponentProperty(
                  iSessionHandle, cid, "Domain-Category",
                  domainCategory, UNSPECIFIED_LOCALE);
        if (err < 0)
        {
            InstallerException.internalError(
                "Adding property Domain-Category value " + domainCategory +
                " for component " + cid + " failed with code " + err);
        }
    }

    /**
     * Returns array of localized names from the specified
     * attributes of given suite. Assumes that aAttrPrefix
     * is an attribute name prefix that is followed by locale.
     * If the same locale is found more than once, localized
     * name for only the last occurrence is returned.
     */
    private LocalizedName[] getLocalizedNames(
        SuiteInfo aSuite, String aAttrPrefix)
    {
        Hashtable localizedNames = new Hashtable();
        Enumeration e = aSuite.getAttributes().elements();
        while (e.hasMoreElements())
        {
            Attribute attr = (Attribute)e.nextElement();
            String name = attr.getName();
            if (name.startsWith(aAttrPrefix))
            {
                String locale = name.substring(aAttrPrefix.length());
                if (isValidLocale(locale))
                {
                    LocalizedName localizedName =
                        new LocalizedName(attr.getValue(), locale);
                    if (localizedName.getLanguage() == -1)
                    {
                        Log.logWarning(
                            "SifRegistrator ignored unknown locale: " +
                            name + ": " + localizedName);
                    }
                    else
                    {
                        Log.log("SifRegistrator found localized text " +
                                name + ": " + localizedName);
                        localizedNames.put(
                            new Integer(localizedName.getLanguage()),
                            localizedName);
                    }
                }
            }
        }
        LocalizedName[] result = new LocalizedName[localizedNames.size()];
        e = localizedNames.elements();
        for (int i = 0; e.hasMoreElements(); i++)
        {
            result[i] = (LocalizedName)e.nextElement();
        }
        return result;
    }

    /**
     * Returns true if given locale is a valid one. Valid locales
     * use two letter ISO language and optionally country codes.
     */
    private boolean isValidLocale(String aLocale)
    {
        boolean result = false;
        if (aLocale.length() == 2)
        {
            // Assume that locale has only language code.
            result = true;
        }
        if (aLocale.length() == 5)
        {
            // Assume that locale has language and country codes.
            char separator = aLocale.charAt(2);
            if (separator == '-' || separator == '_')
            {
                result = true;
            }
        }
        return result;
    }

    /**
     * Returns a string which can be stored to S60 SCR. This method ensures
     * that the length of the returned string does not exceed the maximum
     * length limit set by SCR (512 characters).
     */
    private static String getScrString(String aStr)
    {
        final int maxLen = 512;
        if (aStr != null && aStr.length() > maxLen)
        {
            return aStr.substring(0, maxLen);
        }
        return aStr;
    }

    /*** ----------------------------- NATIVE ----------------------------- */

    /**
     * Notifies system about added/updated/removed applications.
     * This method should be called only after the changes have been
     * committed.
     *
     * @param aAppUids application uids
     * @param aAppChange change type: APP_ADDED, APP_UPDATED, or APP_REMOVED
     * @return 0 or Symbian error code (negative number)
     */
    private static native int _notifyAppChange(int[] aAppUids, int aAppChange);

    /**
     * Launches the applications view.
     *
     * @return 0 or Symbian error code (negative number)
     */
    private static native int _launchAppView();

    /**
     * Registers Java software type to software installation framework.
     *
     * @param aRegister true for registration, false for unregistration
     * @return 0 or Symbian error code (negative number)
     */
    private static native int _registerJavaSoftwareType(boolean aRegister);

    /**
     * Starts native application registration session.
     *
     * @param aTransaction true if also transaction for this session should
     * be opened, false otherwise
     * @return native session handle or Symbian error code (negative number)
     */
    private static native int _startSession(boolean aTransaction);

    /**
     * Commits native application registration session.
     * If commit succeeds the native session is closed.
     *
     * @param aSessionHandle
     * @param aSynchronous if true, makes synchronous commit
     * @return 0 or Symbian error code (negative number)
     */
    private static native int _commitSession(int aSessionHandle);

    /**
     * Rolls back and closes native application registration session.
     *
     * @param aSessionHandle
     * @return 0 or Symbian error code (negative number)
     */
    private static native int _rollbackSession(int aSessionHandle);

    /**
     * Closes native application registration session.
     *
     * @param aSessionHandle the session to be closed
     */
    private static native void _closeSession(int aSessionHandle);

    /**
     * Registers Java application to S60 USIF as a component.
     *
     * @param aSessionHandle
     * @param aUid
     * @param aSuiteName
     * @param aVendor
     * @param aVersion
     * @param aName
     * @param aGlobalId
     * @param aComponentFiles
     * @param aComponentSize
     * @param aIsRemovable
     * @param aIsDrmProtected
     * @param aIsOriginVerified
     * @param aIsUpdate
     * @param aMediaId
     * @param aMidletInfoUrl
     * @param aMidletDescription
     * @param aDownloadUrl
     * @param aComponentId upon successful execution contains the
     * component id for the registered component
     * @return 0 if registration succeeded or Symbian error code
     */
    private static native int _registerComponent(
        int aSessionHandle, int aUid, String aSuiteName, String aVendor,
        String aVersion, String aName, String aGlobalId,
        String[] aComponentFiles, long aComponentSize,
        boolean aIsRemovable, boolean aIsDrmProtected,
        boolean aIsOriginVerified, boolean aIsUpdate, int aMediaId,
        String aMidletInfoUrl, String aMidletDescription, String aDownloadUrl,
        ComponentId aComponentId);

    /**
     * Unregisters Java application from S60 USIF.
     *
     * @param aSessionHandle
     * @param aComponentId The component id of the application
     * @return 0 if unregistration succeeded or Symbian error code
     */
    private static native int _unregisterComponent(
        int aSessionHandle, int aComponentId);

    /**
     * Registers Java application to S60 USIF as an application
     * inside specified component.
     *
     * @param aSessionHandle
     * @param aCid
     * @param aAppUid
     * @param aAppName
     * @param aAppFilename
     * @param aGroupName
     * @param aIconFilename
     * @param aNumberOfIcons
     * @param aLanguages
     * @param aAppNames
     * @return 0 if registration succeeded or Symbian error code
     */
    private static native int _registerApplication(
        int aSessionHandle, int aCid, int aAppUid, String aAppName,
        String aAppFilename, String aGroupName, String aIconFilename,
        int aNumberOfIcons, int[] aLanguages, String[] aAppNames);

    /**
     * Registers localized name and vendor for specified component.
     *
     * @param aSessionHandle
     * @param aCid component id
     * @param aName localized component name
     * @param aVendor localized component vendor (can be null)
     * @param aLanguage S60 language code
     * @return 0 if unregistration succeeded or Symbian error code
     */
    private static native int _registerLocalizedComponentName(
        int aSessionHandle, int aCid, String aName, String aVendor, int aLanguage);

    /**
     * Sets localized property value for specified component.
     *
     * @param aSessionHandle
     * @param aCid component id
     * @param aName property name
     * @param aValue localized property value
     * @param aLanguage S60 language code
     * @return 0 if unregistration succeeded or Symbian error code
     */
    private static native int _setLocalizedComponentProperty(
        int aSessionHandle, int aCid, String aName, String aValue, int aLanguage);

    /**
     * Returns the component id of the application.
     *
     * @param aSessionHandle
     * @param aGlobalId
     * @param aComponentId contains component id after successful function call
     * @return Symbian error code (negative number) if fails, otherwise 0
     */
    private static native int _getComponentId(
        int aSessionHandle, String aGlobalId, ComponentId aComponentId);

    /**
     * Returns the component id of the application.
     *
     * @param aSessionHandle
     * @param aAppUid
     * @param aComponentId contains component id after successful function call
     * @return Symbian error code (negative number) if fails, otherwise 0
     */
    private static native int _getComponentIdForApp(
        int aSessionHandle, int aAppUid, ComponentId aComponentId);

    /**
     * Returns the uid of the component.
     *
     * @param aSessionHandle
     * @param aCid component id
     * @param aUid contains uid after successful function call
     * @return Symbian error code (negative number) if fails, otherwise 0
     */
    private static native int _getUid(int aCid, ComponentId aUid);

    /**
     * Writes information of the given application to JavaInstaller log.
     *
     * @param aSessionHandle
     * @param aGlobalId the global id for the application
     * @return Symbian error code (negative number) if fails, otherwise 0
     */
    private static native int _logComponent(
        int aSessionHandle, String aGlobalId);

    /**
     * Checks if USIF is enabled.
     *
     * @return 1 if application data should be registered to USIF, 0 otherwise
     */
    private static native int _getUsifMode();
}
