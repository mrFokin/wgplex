package rpc

/*
#include <stdlib.h>
#include <string.h>
#include <membership.h>
*/
import "C"

import (
	"fmt"
	"strconv"
	"syscall"
	"unsafe"
)

// IsMember reports whether uid is a member of group through Directory
// Services (design 5): mbr_uid_to_uuid for uid, mbr_identifier_to_uuid for the
// group, then mbr_check_membership, which sees nested groups and membership
// changes at once and needs no root. group is a name (ID_TYPE_GROUPNAME) or,
// when it is all digits, a gid (ID_TYPE_GID with a gid_t identifier, not a
// string). A group that is not found (ENOENT) is "not a member", nil error;
// any other failure is an error. A thin layer without logic of its own:
// checked in the VM.
func IsMember(uid uint32, group string) (bool, error) {
	var user, grp C.uuid_t
	if rc := C.mbr_uid_to_uuid(C.uid_t(uid), &user[0]); rc != 0 {
		return false, fmt.Errorf("mbr_uid_to_uuid(%d): %w", uid, syscall.Errno(rc))
	}

	var rc C.int
	if gid, err := strconv.ParseUint(group, 10, 32); err == nil {
		g := C.gid_t(gid)
		rc = C.mbr_identifier_to_uuid(C.ID_TYPE_GID, unsafe.Pointer(&g), C.size_t(unsafe.Sizeof(g)), &grp[0])
	} else {
		name := C.CString(group)
		defer C.free(unsafe.Pointer(name))
		rc = C.mbr_identifier_to_uuid(C.ID_TYPE_GROUPNAME, unsafe.Pointer(name), C.strlen(name), &grp[0])
	}
	switch {
	case syscall.Errno(rc) == syscall.ENOENT:
		return false, nil
	case rc != 0:
		return false, fmt.Errorf("mbr_identifier_to_uuid(%q): %w", group, syscall.Errno(rc))
	}

	var member C.int
	if rc := C.mbr_check_membership(&user[0], &grp[0], &member); rc != 0 {
		return false, fmt.Errorf("mbr_check_membership(%d, %q): %w", uid, group, syscall.Errno(rc))
	}
	return member != 0, nil
}
