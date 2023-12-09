/*
* Copyright (c) 2008-2009 Nokia Corporation and/or its subsidiary(-ies).
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


package com.nokia.mj.impl.installer.midp2.install.steps;

import com.nokia.mj.impl.installer.exetable.ExeBall;
import com.nokia.mj.impl.installer.exetable.ExeStep;
import com.nokia.mj.impl.installer.storagehandler.SuiteInfo;
import com.nokia.mj.impl.installer.utils.Log;
import com.nokia.mj.impl.rt.installer.ApplicationInfoImpl;
import com.nokia.mj.impl.rt.support.ApplicationInfo;
import com.nokia.mj.impl.security.midp.authentication.AuthenticationModule;
import com.nokia.mj.impl.security.packageprotection.PackageProtector;
import com.nokia.mj.impl.security.packageprotection.ScanCheck;

public class CheckJarPackages extends ExeStep
{
    public void execute(ExeBall aBall)
    {
        InstallBall ball = (InstallBall)aBall;

        // Let the security framework know the unique id of
        // the installation drive. This is needed to determine
        // if tamper detection is needed.
        AuthenticationModule.getInstance().setMediaId(
            ball.iStorageHandler.getSession(),
            ball.iSuite.getUid(), ball.iSuite.getMediaId());

        // Application package scanning must be skipped if instructed so
//        if (ball.iArgs.get("skipjarcheck") != null)
//        {
//            Log.log("Skipping application package check");
//            return;
//        }

        // Jar packages check must be skipped in preinstallation
        // of manufacturer and operator domain applications
        // to optimize preinstallation performance.
//        String domain = null;
//        if (ball.iAuthenticationCredentials != null)
//        {
//            for (int i = 0; i < ball.iAuthenticationCredentials.length; i++)
//            {
//                domain = ball.iAuthenticationCredentials[i]
//                         .getProtectionDomainCategory();
//                Log.log("Protection domain: " + domain);
//            }
//        }
        String domain = AuthenticationModule.getForcedDomainCategory();
        if (domain != null)
        {
            // Set domain to ApplicationInfo so that possible installation
            // time security prompts display correct security icons.
            ApplicationInfoImpl appInfoImpl =
                (ApplicationInfoImpl)ApplicationInfo.getInstance();
            appInfoImpl.setProtectionDomain(domain);
        }

        // Application touch support detection is not needed
        // if Nokia-MIDlet-On-Screen-Keypad has been defined.
        boolean touchDetection = true;
        if (ball.getAttributeValue("Nokia-MIDlet-On-Screen-Keypad") != null &&
            ball.iSuite.getOnScreenKeypad() != SuiteInfo.OSK_UNDEFINED)
        {
            touchDetection = false;
        }

        // Application package scanning must not be skipped for
        // preinstalled applications when application touch support
        // detection is needed.
        if (!touchDetection && ball.iPreinstallation && domain != null &&
                (domain.equals(ApplicationInfo.MANUFACTURER_DOMAIN) ||
                 domain.equals(ApplicationInfo.OPERATOR_DOMAIN)))
        {
            Log.log("Skipping application package check for " + domain +
                    " domain application during preinstallation");
            return;
        }

        ScanCheck scanChecks = null;
        if (touchDetection)
        {
            // Automatic touch support detection: if the application
            // implements a class which inherits from Canvas and
            // implements any of pointerDragged, pointerPressed,
            // or pointerReleased methods, assume that the
            // application is touch enabled and disable the
            // on-screen-keypad.
            ScanCheck.BaseClassCheck[] baseClassChecks =
                new ScanCheck.BaseClassCheck[]
            {
                new ScanCheck.BaseClassCheck("javax/microedition/lcdui/Canvas"),
                new ScanCheck.BaseClassCheck("javax/microedition/lcdui/game/GameCanvas"),
                new ScanCheck.BaseClassCheck("com/nokia/mid/ui/FullCanvas"),
            };
            ScanCheck.MethodCheck[] methodChecks = new ScanCheck.MethodCheck[]
            {
                new ScanCheck.MethodCheck("pointerDragged", "(II)V"),
                new ScanCheck.MethodCheck("pointerPressed", "(II)V"),
                new ScanCheck.MethodCheck("pointerReleased", "(II)V"),
            };
            scanChecks = new ScanCheck(baseClassChecks, methodChecks);
        }
        else
        {
            Log.log("Touch detection is disabled");
        }
        ball.log("Checking application packages for " + ball.iJarFilename);
        PackageProtector pp = PackageProtector.getInstance();
        pp.scanApplication(ball.iJarFilename, scanChecks);
        // Check the scanCheck results.
        if (touchDetection && isTouchEnabled(scanChecks))
        {
            Log.log("Application is touch enabled, disabling on-screen-keypad");
            ball.iSuite.setOnScreenKeypad(SuiteInfo.OSK_NO);
        }
    }

    public void cancel(ExeBall aBall)
    {
        // nop
    }

    private boolean isTouchEnabled(ScanCheck aScanCheck)
    {
        Log.log("isTouchEnabled:\n" + aScanCheck);
        // Loop through matching methods and check if it is a
        // Canvas class which implements them.
        for (int i = 0; i < aScanCheck.iMethodChecks.length; i++)
        {
            ScanCheck.MethodCheckResult[] methodResults =
                aScanCheck.iMethodChecks[i].iResults;
            if (methodResults != null && methodResults.length > 0)
            {
                for (int j = 0; j < methodResults.length; j++)
                {
                    ScanCheck.MethodCheckResult methodResult = methodResults[j];
                    if (methodResult.iCodeLength <= 1)
                    {
                        // Method has an empty implementation, ignore it.
                        continue;
                    }
                    if (isCanvasClass(methodResult.iClassName, aScanCheck))
                    {
                        // There is a class which inherits from Canvas
                        // and which implements one of the touch
                        // methods, so assume that application
                        // is touch enabled and disable the
                        // on-screen-keypad.
                        Log.log("Class " + methodResult.iClassName +
                                " inherits from Canvas and implements " +
                                aScanCheck.iMethodChecks[i].iMethodName +
                                " of code length " +
                                methodResult.iCodeLength);
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private boolean isCanvasClass(String aClassName, ScanCheck aScanCheck)
    {
        for (int i = 0; i < aScanCheck.iBaseClassChecks.length; i++)
        {
            if (aScanCheck.iBaseClassChecks[i].iClassNames != null)
            {
                for (int j = 0;
                        j < aScanCheck.iBaseClassChecks[i].iClassNames.length;
                        j++)
                {
                    if (aClassName.equals(
                                aScanCheck.iBaseClassChecks[i].iClassNames[j]))
                    {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
