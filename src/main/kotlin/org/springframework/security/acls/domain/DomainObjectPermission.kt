/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.acls.domain

import org.springframework.util.Assert
import java.io.Serializable

/**
 * Represents a permission setting per user for a domain object referenced by the {@link MongoAcl} instance which
 * holds instances of this class.
 * <p>
 * This class is a mapping class for {@link org.springframework.security.acls.model.AccessControlEntry} instances which
 * are persisted into a MongoDB database. Instead of keeping the data separated into different collections, similar to
 * the SQL approach, permissions are embedded into the Mongo ACL entry. This is necessary as MongoDB does not support
 * table joins, like SQL does, and also keeps data that belong to each other within the same collection entry to avoid
 * lookup time.
 *
 * @author Roman Vottner
 * @author Soumik Kumar Saha
 * @since 4.3
 */
class DomainObjectPermission(
    private val id: Serializable?,
    private val sid: MongoSid,
    private var permission: Int,
    private val granting: Boolean,
    private var auditSuccess: Boolean,
    private var auditFailure: Boolean,
) {
    init {
        Assert.notNull(sid, "Sid required")
    }

    /**
     * Returns the unique identifier of this user permission entry.
     *
     * @return The unique identifier of this permission entry
     */
    fun getId(): Serializable? = id

    /**
     * Returns the permissions of the user identified by [sid] as bit mask.
     *
     * @return The user access permissions as bit mask
     */
    fun getPermission(): Int = permission

    /**
     * Returns the security identity this permission entry was created for.
     *
     * @return The user this permission is for
     */
    fun getSid(): MongoSid = sid

    /**
     * Defines whether a failed access on a domain object by this user should be logged.
     *
     * @return true if failed domain object access should be logged; false otherwise
     */
    fun isAuditFailure(): Boolean = auditFailure

    /**
     * Defines whether successful domain object access by this user should be logged.
     *
     * @return true if successful domain object access should be logged; false otherwise
     */
    fun isAuditSuccess(): Boolean = auditSuccess

    /**
     * Specifies whether the permissions returned by [getPermission] are for a granting or rejecting purpose.
     *
     * @return true if permissions returned by [getPermission] specify granting permissions;
     *         false will state that permissions returned by [getPermission] are for rejecting a user on a match.
     */
    fun isGranting(): Boolean = granting

    /**
     * Specifies whether failed domain object access should be logged.
     *
     * @param auditFailure true if failed domain object access should be logged; false otherwise
     */
    fun setAuditFailure(auditFailure: Boolean) {
        this.auditFailure = auditFailure
    }

    /**
     * Specifies whether successful domain object access should be logged.
     *
     * @param auditSuccess true if successful domain object access should be logged; false otherwise
     */
    fun setAuditSuccess(auditSuccess: Boolean) {
        this.auditSuccess = auditSuccess
    }

    /**
     * Specifies the access permission for the user returned by [getSid] on a domain object held by the ACL
     * that holds this permission entry.
     *
     * Access control permissions can be chained together using the bit-operator '|' like in the sample below
     * which defines read and write access for a certain user:
     * `BasePermission.READ.getMask() or BasePermission.WRITE.getMask()`
     *
     * @param permission The permission set for a certain user
     */
    fun setPermission(permission: Int) {
        this.permission = permission
    }

    override fun toString(): String =
        "DomainObjectPermission[id = $id, sid = $sid, permission = $permission, granting = $granting, " +
            "auditSuccess = $auditSuccess, auditFailure = $auditFailure]"
}
