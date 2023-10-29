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
import com.nokia.mj.impl.installer.utils.Log;
import com.nokia.mj.impl.security.midp.authentication.AuthenticationModule;

import java.util.Vector;

/**
 * MIDP installation step RegisterApplicationToSif.
 */
public class RegisterApplicationToSif extends ExeStep
{
	
    public void execute(ExeBall aBall)
    {
        InstallBall ball = (InstallBall)aBall;

        if (ball.iOldSuite != null)
        {
            // Old suite exists, unregister it first.
            ball.iSifRegistrator.unregisterSuite(ball.iOldSuite);
            Log.log("Old suite unregistered from SIF");
        }

        /*if (ball.iAuthenticationCredentials != null)
        {
            // Set protection domain name.
            ball.iSuite.setProtectionDomainName(
                ball.iAuthenticationCredentials[0].getProtectionDomainName());
        }*/
        ball.iSuite.setProtectionDomainName(AuthenticationModule.getForcedDomainName());

        // Initialize application installation group to SuiteInfo.
        // Note that ball.iInstallationGroup is initialized
        // in RegisterApplication step, so it must be executed
        // before this step.
        ball.iSuite.setInstallationGroup(ball.iInstallationGroup);

        // Register the applications in the suite.
        ball.iSifRegistrator.registerSuite(
            ball.iSuite, ball.iOldSuite != null);
        Log.log("Suite registered to SIF");

        // Log the registered suite and applications.
        ball.iSifRegistrator.logComponent(ball.iSuite.getGlobalId());
        Vector apps = ball.iSuite.getApplications();
        for (int i = 0; i < apps.size(); i++)
        {
            ball.iSifRegistrator.logComponent(ball.iSuite.getGlobalId(i));
        }
    }

    public void cancel(ExeBall aBall)
    {
        // nop
    }
}
