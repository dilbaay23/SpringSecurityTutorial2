package com.moon.springsecuritytutorial2.security;

import com.google.common.collect.Sets;


import java.util.Set;

import static com.moon.springsecuritytutorial2.security.ApplicationUserPermission.*;

/**
 * Created by Moon on 12/9/2020
 */
public enum ApplicationUserRole {
    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(COURSE_READ,COURSE_WRITE,STUDENT_READ,STUDENT_WRITE)),
    ADMINTRAINEE(Sets.newHashSet(COURSE_READ,STUDENT_READ));


    private final Set<ApplicationUserPermission> permissions;

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationUserPermission> getPermissions() {
        return permissions;
    }
}
