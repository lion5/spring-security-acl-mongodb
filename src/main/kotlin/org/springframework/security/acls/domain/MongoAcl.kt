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

import org.springframework.data.annotation.Id
import org.springframework.data.mongodb.core.index.CompoundIndex
import org.springframework.data.mongodb.core.index.CompoundIndexes
import org.springframework.data.mongodb.core.index.Indexed
import org.springframework.data.mongodb.core.mapping.Document
import org.springframework.security.core.context.SecurityContextHolder
import java.io.Serializable
import java.util.ArrayList

/**
 * Represents an access control list configuration for a domain object specified by its unique identifier. An instance
 * of this class defines an owner of a domain object, a parent ACL configuration instance, which it may inherit
 * permissions from, as well as a list of user permissions for the referenced domain object.
 * <p>
 * This class is a mapping class for {@link Acl} instances which should be persisted to a MongoDB database.
 *
 * @author Roman Vottner
 * @author Soumik Kumar Saha
 * @since 4.3
 */
@CompoundIndexes(
    CompoundIndex(name = "domainObject", def = "{'instanceId' : 1, 'className' : 1}"),
)
@Document(collection = "ACL")
class MongoAcl {
    /**
     * The unique identifier of the ACL pointing to some domain object
     */
    @Id
    var id: Serializable? = null

    /**
     * The fully qualified class name of the domain object
     */
    var className: String? = null

    /**
     * A reference to the unique identifier of the domain object this ACL was created for
     */
    var instanceId: Serializable? = null

    /**
     * The unique identifier of the user owning the domain object
     */
    var owner: MongoSid? = null

    /**
     * A reference to a parent ACL which may inherit permissions. Can be null
     */
    @Indexed
    var parentId: Serializable? = null

    /**
     * Defines whether to inherit permissions from parent ACL or not. If set to true permissions will be inherited from
     * parent ACLs
     */
    var inheritPermissions = true

    /**
     * A list containing access control permissions per user on the domain object this ACL references to
     */
    var permissions: MutableList<DomainObjectPermission> = ArrayList()

    constructor() {}

    /**
     * Creates a new access control list instance for a domain object identified by the given [instanceId] unique
     * identifier. The class of the domain object is identified via the provided [className] argument. This
     * constructor will set the currently authenticated user as the owner of the domain object identified by the passed
     * [instanceId].
     *
     * @param instanceId The unique identifier of the domain object a new access control list should be generated for
     * @param className  The fully qualified class name of the domain object
     * @param id         The unique identifier of this access control list
     */
    constructor(instanceId: Serializable?, className: String?, id: Serializable?) {
        this.id = id
        this.instanceId = instanceId
        this.className = className
        // assign the user who created the object as owner
        val ownerName = SecurityContextHolder.getContext().authentication.name
        owner = MongoSid(ownerName)
    }

    /**
     * Creates a new access control list instance for a domain object identified by the given [instanceId] unique
     * identifier. The class of the domain object is identified via the provided [className] argument.
     *
     * @param instanceId        The unique identifier of the domain object a new access control list should be generated
     * for
     * @param className         The fully qualified class name of the domain object
     * @param id                The unique identifier of this access control list
     * @param owner             The owner of the domain object. Note an owner has full access to the domain object
     * @param parentId          A unique identifier to a parent access control list which contains permissions which are
     * inherited if [entriesInheriting] argument is set to true
     * @param entriesInheriting If set to true will include checking permissions from ancestor access control list
     * entries
     */
    constructor(
        instanceId: Serializable?,
        className: String?,
        id: Serializable?,
        owner: MongoSid?,
        parentId: Serializable?,
        entriesInheriting: Boolean,
    ) : this(instanceId, className, id) {
        this.parentId = parentId
        this.owner = owner
        inheritPermissions = entriesInheriting
    }

    override fun toString(): String =
        "MongoAcl[id = $id, className = $className, instanceId = $instanceId, parentId = $parentId, " +
            "inheritPermissions = $inheritPermissions, owner = $owner, permissions = $permissions]"
}
