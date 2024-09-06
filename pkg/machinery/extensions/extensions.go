// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package extensions contains Talos extensions specific API.
package extensions

// AllowedPaths lists paths allowed in the extension images.
var AllowedPaths = []string{
	"/etc/cri/conf.d",
	"/lib/firmware",
	"/lib/modules",
	// The glibc loader is required by glibc dynamic binaries.
	"/lib64/ld-linux-x86-64.so.2",
	// /sbin/ldconfig is required by the nvidia container toolkit.
	"/sbin/ldconfig",
	"/usr/etc/udev/rules.d",
	"/usr/local",
	// glvnd, egl and vulkan are needed for OpenGL/Vulkan.
	"/usr/share/glvnd",
	"/usr/share/egl",
	"/etc/vulkan",
}
