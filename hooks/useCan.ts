import { useContext } from "react";
import { AuthContext } from "../contexts/AuthContex";
import { validateUserPermission } from "../utils/validateUserPermissions";

interface UseCanParams {
  permissions?: string[];
  roles?: string[];
}

export function useCan({ permissions, roles }: UseCanParams) {
  const { user, isAuthenticated } = useContext(AuthContext);

  if (!isAuthenticated) {
    return false;
  }
  const userHasValidPermissions = validateUserPermission({
    user,
    permissions,
    roles,
  })

  return userHasValidPermissions;
}