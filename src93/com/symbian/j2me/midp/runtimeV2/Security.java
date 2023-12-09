package com.symbian.j2me.midp.runtimeV2;

import com.symbian.j2me.framework.Framework;
import com.symbian.j2me.net.URI;
import java.util.Hashtable;
import java.util.Vector;

final class Security {
	private SecurityPolicy iPolicy;
	private Hashtable iGrantedPermissions;
	private Hashtable iDeniedPermissions;
	private Hashtable iUserPermissions;
	private static Security sInstance;

	public static void ensureAutoLaunchPermission(String aOperation, String[] aArgs) throws SecurityException {
		sInstance.ensureAutoLaunchPermissionInternal(aOperation, aArgs);
	}

	private static URI newURI(String aURI) {
		URI uri = null;
		try {
			uri = new URI(aURI);
		} catch (IllegalArgumentException localIllegalArgumentException) {
		}
		return uri;
	}

	int driveForRoot(String aRoot) {
		return this.iPolicy.driveForRoot(aRoot);
	}

	boolean driveAccessible(int aDrive) {
		return this.iPolicy.driveAccessible(aDrive);
	}

	String rootForDrive(int aDrive) {
		return this.iPolicy.rootForDrive(aDrive);
	}

	int pathAccess(int aDrive, String aPath) {
		return this.iPolicy.pathAccess(aDrive, aPath);
	}

	String[] rootDirectoryList(int aDrive) {
		return this.iPolicy.rootDirectoryList(aDrive);
	}

	String mapPath(int aDrive, String aPath) {
		return this.iPolicy.mapPath(aDrive, aPath);
	}

	synchronized int checkPermission(String aPermission) {
		return 1;
//		if (this.iGrantedPermissions.get(aPermission) != null) {
//			return 1;
//		}
//		if (this.iDeniedPermissions.get(aPermission) != null) {
//			return 0;
//		}
//		if (this.iUserPermissions.get(aPermission) != null) {
//			return -1;
//		}
//		this.iDeniedPermissions.put(aPermission, aPermission);
//		return 0;
	}

	private synchronized void ensureAutoLaunchPermissionInternal(String aOperation, String[] aArgs)
			throws SecurityException {
//		String permissionName = "javax.microedition.io.PushRegistry";
//		if (this.iGrantedPermissions.get(permissionName) != null) {
//			return;
//		}
//		if (this.iDeniedPermissions.get(permissionName) != null) {
//			deny(permissionName);
//		}
//		if (this.iUserPermissions.get(permissionName) != null) {
//			if (!getUserAutoLaunchPermission(permissionName, aOperation, aArgs)) {
//				deny(permissionName);
//			}
//			return;
//		}
//		deny(permissionName);
	}
	
	  synchronized int getUserPermissionDoNotPrompt(String aPermission)
	  {
//	    int userPermission = this.iPolicy.getUserPermissionDoNotPrompt(aPermission);
//	    int result = 0;
//	    switch (userPermission)
//	    {
//	    case 0: 
//	      result = 0;
//	      break;
//	    case 1: 
//	      result = -1;
//	      break;
//	    case 2: 
//	      result = 1;
//	      break;
//	    default: 
//	      result = 0;
//	    }
	    int result = 1;
	    return result;
	  }

	synchronized void ensurePermission(String aPermissionName, String aOperation, String[] aArgs)
			throws SecurityException {
//		if (this.iGrantedPermissions.get(aPermissionName) != null) {
//			return;
//		}
//		if (this.iDeniedPermissions.get(aPermissionName) != null) {
//			deny(aPermissionName);
//		}
//		if (this.iUserPermissions.get(aPermissionName) != null) {
//			if (!getUserPermission(aPermissionName, aOperation, aArgs)) {
//				deny(aPermissionName);
//			}
//			return;
//		}
//		deny(aPermissionName);
	}

	void ensureConnectionAccess(String aURI) {
		ensureConnectionAccess(new URI(aURI, false));
	}

	synchronized void ensureConnectionAccess(URI aURI) throws SecurityException {
//		if (this.iPolicy.blocked(aURI)) {
//			throw new SecurityException();
//		}
	}

	synchronized void ensureConnectionPermission(URI aURI, String aPermissionName, String aOperation, String[] aArgs)
			throws SecurityException {
		if (aURI != null) {
			ensureConnectionAccess(aURI);
		}
		ensurePermission(aPermissionName, aOperation, aArgs);
	}

	private boolean getUserAutoLaunchPermission(String aPermission, String aOperation, String[] aArgs) {
		boolean havePermission = false;
		int userPermission = this.iPolicy.getUserAutoLaunchPermission(aPermission, aOperation, aArgs);
		switch (userPermission) {
		case 0:
			this.iUserPermissions.remove(aPermission);
			this.iDeniedPermissions.put(aPermission, aPermission);
			break;
		case 1:
			break;
		case 2:
			this.iUserPermissions.remove(aPermission);
			this.iGrantedPermissions.put(aPermission, aPermission);
			havePermission = true;
			break;
		case 3:
			havePermission = true;
		}
		return havePermission;
	}

	private boolean getUserPermission(String aPermission, String aOperation, String[] aArgs) {
		boolean havePermission = false;
		int userPermission = this.iPolicy.getUserPermission(aPermission, aOperation, aArgs);
		switch (userPermission) {
		case 0:
			this.iUserPermissions.remove(aPermission);
			this.iDeniedPermissions.put(aPermission, aPermission);
			break;
		case 1:
			break;
		case 2:
			this.iUserPermissions.remove(aPermission);
			this.iGrantedPermissions.put(aPermission, aPermission);
			havePermission = true;
			break;
		case 3:
			havePermission = true;
			break;
		case 1001:
			throw new SecurityDialogDismissed();
		}
		return havePermission;
	}

	private static void deny(String aPermission) {
		throw new SecurityException("Permission = ".concat(aPermission));
	}

	static Security initialize(Framework aFramework, MIDletSuite aMIDletSuite, SecurityPolicy aPolicy)
			throws SecurityException {
		sInstance = new Security(aPolicy);
		sInstance.initialize(aMIDletSuite);
		return sInstance;
	}

	static Security initializeUntrusted(Framework aFramework, MIDletSuite aMIDletSuite, SecurityPolicy aPolicy) {
		sInstance = new Security(aPolicy);
		sInstance.initializeUntrusted(aMIDletSuite);
		return sInstance;
	}

	private Security(SecurityPolicy aPolicy) {
		this.iPolicy = aPolicy;
		this.iGrantedPermissions = new Hashtable();
		this.iDeniedPermissions = new Hashtable();
		this.iUserPermissions = new Hashtable();
	}

	private void initialize(MIDletSuite aMIDletSuite) {
		initializePermissions(aMIDletSuite.getRequestedPermissions());
	}

	private void initializeUntrusted(MIDletSuite aMIDletSuite) {
		String[] permissions = this.iPolicy.getGrantedPermissions();
		int permissionCount = permissions.length;
		for (int i = 0; i < permissionCount; i++) {
			String permission = permissions[i];

			this.iGrantedPermissions.put(permission, permission);
		}
		permissions = this.iPolicy.getDeniedPermissions();
		permissionCount = permissions.length;
		for (int i = 0; i < permissionCount; i++) {
			String permission = permissions[i];

			this.iDeniedPermissions.put(permission, permission);
		}
		permissions = this.iPolicy.getUserPermissions();
		permissionCount = permissions.length;
		for (int i = 0; i < permissionCount; i++) {
			String permission = permissions[i];

			this.iUserPermissions.put(permission, permission);
		}
	}

	private void initializePermissions(Vector aRequestedPermissions) {
		initializePermissionTable(this.iGrantedPermissions, this.iPolicy
				.getGrantedPermissions(), aRequestedPermissions);

		initializePermissionTable(this.iDeniedPermissions, this.iPolicy.getDeniedPermissions(), aRequestedPermissions);

		initializePermissionTable(this.iUserPermissions, this.iPolicy.getUserPermissions(), aRequestedPermissions);
	}

	private void initializePermissionTable(Hashtable aTable, String[] aPermissions, Vector aRequested) {
		int n = aPermissions.length;
		for (int i = 0; i < n; i++) {
			String permission = aPermissions[i];
			if (aRequested.contains(permission)) {
				aTable.put(permission, permission);
			}
		}
	}
}
