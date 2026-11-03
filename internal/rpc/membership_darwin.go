package rpc

/*
#include <membership.h>
*/
import "C"

// IsMember reports whether uid is a member of group through Directory
// Services (design 5): mbr_uid_to_uuid for uid, mbr_identifier_to_uuid for the
// group, then mbr_check_membership, which sees nested groups and membership
// changes at once and needs no root. group is a name (ID_TYPE_GROUPNAME) or,
// when it is all digits, a gid (ID_TYPE_GID with a gid_t identifier, not a
// string). A group that is not found (ENOENT) is "not a member", nil error;
// any other failure is an error. A thin layer without logic of its own:
// checked in the VM.
func IsMember(uid uint32, group string) (bool, error) {
	panic("not implemented")
}
