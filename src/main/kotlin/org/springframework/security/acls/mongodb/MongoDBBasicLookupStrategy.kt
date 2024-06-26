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
package org.springframework.security.acls.mongodb

import org.springframework.data.domain.Sort
import org.springframework.data.mongodb.core.MongoTemplate
import org.springframework.data.mongodb.core.query.Criteria
import org.springframework.data.mongodb.core.query.Query
import org.springframework.security.acls.domain.MongoAcl
import org.springframework.security.acls.domain.AccessControlEntryImpl
import org.springframework.security.acls.domain.AclAuthorizationStrategy
import org.springframework.security.acls.domain.AclImpl
import org.springframework.security.acls.domain.AuditLogger
import org.springframework.security.acls.domain.DefaultPermissionFactory
import org.springframework.security.acls.domain.DefaultPermissionGrantingStrategy
import org.springframework.security.acls.domain.GrantedAuthoritySid
import org.springframework.security.acls.domain.ObjectIdentityImpl
import org.springframework.security.acls.domain.PermissionFactory
import org.springframework.security.acls.domain.PrincipalSid
import org.springframework.security.acls.jdbc.LookupStrategy
import org.springframework.security.acls.model.Acl
import org.springframework.security.acls.model.AclCache
import org.springframework.security.acls.model.MutableAcl
import org.springframework.security.acls.model.ObjectIdentity
import org.springframework.security.acls.model.PermissionGrantingStrategy
import org.springframework.security.acls.model.Sid
import org.springframework.security.util.FieldUtils
import org.springframework.util.Assert
import java.io.Serializable

/**
 * Performs lookups against a MongoDB data store. This strategy class will take care of reading a POJO representation of
 * ACL documents from a MongoDB database and converting the results to proper Spring Security ACL instances. As with the
 * SQL based lookup strategy implementation, this implementation will make use of caching retrieved ACLs and providing
 * cached results on subsequent queries.
 * <p>
 * Note: Similar to the SQL based version of the basic lookup strategy, this implementation will ignore any list
 * containing {@link Sid Sids} passed in as arguments in {@link #readAclsById(List, List)}.
 *
 * @author Roman Vottner
 * @author Soumik Kumar Saha
 * @since 4.3
 */
class MongoDBBasicLookupStrategy(
    private val mongoTemplate: MongoTemplate,
    private val aclCache: AclCache,
    private val aclAuthorizationStrategy: AclAuthorizationStrategy,
    private val grantingStrategy: PermissionGrantingStrategy,
) : LookupStrategy {
    /**
     * Used to convert the int value containing the permission value back to a permission object used by Spring security
     */
    private var permissionFactory: PermissionFactory = DefaultPermissionFactory()

    /**
     * The number of ACLs retrieved at maximum in one go
     */
    private val batchSize = 50

    /**
     * Used to add respective user permissions on a domain object to an ACL instance as the setter requires elevated
     * permission and the actual list returned is a copy and hence adding the permission to the list does not work that
     * way
     */
    private val fieldAces = FieldUtils.getField(AclImpl::class.java, "aces")

    init {
        fieldAces.isAccessible = true
    }

    constructor(
        mongoTemplate: MongoTemplate,
        aclCache: AclCache,
        aclAuthorizationStrategy: AclAuthorizationStrategy,
        auditLogger: AuditLogger,
    ) : this(mongoTemplate, aclCache, aclAuthorizationStrategy, DefaultPermissionGrantingStrategy(auditLogger))

    override fun readAclsById(
        objects: List<ObjectIdentity>,
        sids: List<Sid>?,
    ): Map<ObjectIdentity, Acl> {
        val result = HashMap<ObjectIdentity, Acl>()
        val currentBatchToLoad = HashSet<ObjectIdentity>()

        for ((i, oid) in objects.withIndex()) {
            var aclFound = false

            // Check we don't already have this ACL in the results
            if (oid in result) {
                aclFound = true
            }

            // Check cache for the present ACL entry
            if (!aclFound) {
                val acl = aclCache.getFromCache(oid)

                // Ensure any cached element supports all the requested SIDs
                // (they should always, as our base impl doesn't filter on SID)
                if (acl != null) {
                    if (acl.isSidLoaded(sids)) {
                        if (definesAccessPermissionsForSids(acl, sids)) {
                            result[oid] = acl
                            aclFound = true
                        }
                    } else {
                        throw IllegalStateException(
                            "Error: SID-filtered element detected when implementation " +
                                "does not perform SID filtering - have you added something to the cache manually?",
                        )
                    }
                }
            }

            // Load the ACL from the database
            if (!aclFound) {
                currentBatchToLoad.add(oid)
            }

            // Is it time to load from Mongo the currentBatchToLoad?
            if (currentBatchToLoad.size == batchSize || i + 1 == objects.size) {
                if (currentBatchToLoad.isNotEmpty()) {
                    val loadedBatch = lookupObjectIdentities(currentBatchToLoad, sids)

                    // Add loaded batch (all elements 100% initialized) to results
                    result.putAll(loadedBatch)

                    currentBatchToLoad.clear()
                }
            }
        }

        return result
    }

    /**
     * Looks up a batch of {@code ObjectIdentity}s directly from the database.
     * <p>
     * The caller is responsible for optimization issues, such as selecting the identities
     * to lookup, ensuring the cache doesn't contain them already, and adding the returned
     * elements to the cache etc.
     * <p>
     * This subclass is required to return fully valid {@code Acl}s, including
     * properly-configured parent ACLs.
     */
    private fun lookupObjectIdentities(
        objectIdentities: Collection<ObjectIdentity>,
        sids: List<Sid>?,
    ): Map<ObjectIdentity, Acl> {
        Assert.notEmpty(objectIdentities, "Must provide identities to lookup")

        val objectIds = LinkedHashSet<Serializable>()
        val types = LinkedHashSet<String>()
        for (domainObject in objectIdentities) {
            objectIds.add(domainObject.identifier)
            types.add(domainObject.type)
        }
        val where =
            Criteria
                .where("instanceId")
                .`in`(objectIds)
                .and("className")
                .`in`(types)
        val foundAcls =
            mongoTemplate.find(
                Query(where).with(Sort.by(Sort.Direction.ASC, "instanceId", "permissions.position")),
                MongoAcl::class.java,
            )

        val resultMap = HashMap<ObjectIdentity, Acl>()

        for (foundAcl in ArrayList(foundAcls)) {
            val acl =
                try {
                    convertToAcl(foundAcl, foundAcls)
                } catch (cnfEx: ClassNotFoundException) {
                    null // TODO: add exception logging
                }
            if (acl != null && definesAccessPermissionsForSids(acl, sids)) {
                resultMap[acl.objectIdentity] = acl
            }
        }

        return resultMap
    }

    /**
     * Converts the internal MongoDB representation to a Spring Security ACL instance.
     */
    @Throws(ClassNotFoundException::class)
    private fun convertToAcl(
        mongoAcl: MongoAcl,
        foundAcls: MutableList<MongoAcl>,
    ): Acl? {
        var parent: Acl? = null
        if (mongoAcl.parentId != null) {
            var parentAcl = foundAcls.find { it.id == mongoAcl.parentId }
            // if the parent ACL was not loaded already, try to find it via its id
            if (parentAcl == null) {
                mongoAcl.parentId?.let { parentId ->
                    parentAcl = mongoTemplate.findById(parentId as Any, MongoAcl::class.java)
                }
                if (parentAcl != null && parentAcl !in foundAcls) {
                    foundAcls.add(parentAcl!!)
                }
            }
            parent = aclCache.getFromCache(ObjectIdentityImpl(parentAcl?.className, parentAcl?.instanceId))
                ?: parentAcl?.let { convertToAcl(it, foundAcls)?.also { acl -> aclCache.putInCache(acl as MutableAcl) } }
        }
        val objectIdentity = ObjectIdentityImpl(Class.forName(mongoAcl.className), mongoAcl.instanceId)
        val owner =
            if (mongoAcl.owner!!.isPrincipal) {
                PrincipalSid(mongoAcl.owner!!.name)
            } else {
                GrantedAuthoritySid(mongoAcl.owner!!.name)
            }
        val acl =
            AclImpl(
                objectIdentity,
                mongoAcl.id,
                aclAuthorizationStrategy,
                grantingStrategy,
                parent,
                null,
                mongoAcl.inheritPermissions,
                owner,
            )

        mongoAcl.permissions.forEach { permission ->
            val sid =
                if (permission.getSid().isPrincipal) {
                    PrincipalSid(permission.getSid().name)
                } else {
                    GrantedAuthoritySid(permission.getSid().name)
                }
            val permissions = permissionFactory.buildFromMask(permission.getPermission())
            val ace =
                AccessControlEntryImpl(
                    permission.getId(),
                    acl,
                    sid,
                    permissions,
                    permission.isGranting(),
                    permission.isAuditSuccess(),
                    permission.isAuditFailure(),
                )
            // directly adding this permission entry to the Acl isn't possible as the returned list by acl.getEntries()
            // is a copy of the internal list and acl.insertAce(...) requires elevated security permissions
            // acl.getEntries().add(ace);
            // acl.insertAce(acl.getEntries().size(), permissions, user, permission.isGranting);
            val aces = readAces(acl)
            aces.add(ace)
        }

        // add the loaded ACL to the cache
        aclCache.putInCache(acl)

        return acl
    }

    /**
     * Checks whether a fetched ACL specifies any of the {@link Sid Sids} passed in.
     */
    private fun definesAccessPermissionsForSids(
        acl: Acl,
        sids: List<Sid>?,
    ): Boolean {
        // check whether the list of sids is a match-all list or if the owner is found within the list
        if (sids == null || sids.isEmpty() || acl.owner in sids) {
            return true
        }
        // check the contained permissions for permissions granted to a certain user available in the provided list of sids
        if (hasPermissionsForSids(acl, sids)) {
            return true
        }
        // check if a parent reference is available and inheritance is enabled
        return if (acl.parentAcl != null && acl.isEntriesInheriting) {
            definesAccessPermissionsForSids(acl.parentAcl, sids) || hasPermissionsForSids(acl.parentAcl, sids)
        } else {
            false
        }
    }

    /**
     * Checks whether the provided ACL contains permissions issued for any of the given security identities.
     */
    private fun hasPermissionsForSids(
        acl: Acl,
        sids: List<Sid>,
    ): Boolean = acl.entries.any { it.sid in sids }

    private fun readAces(acl: AclImpl): MutableList<AccessControlEntryImpl> {
        try {
            @Suppress("UNCHECKED_CAST")
            return fieldAces.get(acl) as MutableList<AccessControlEntryImpl>
        } catch (e: IllegalAccessException) {
            throw IllegalStateException("Could not obtain AclImpl.aces field", e)
        }
    }

    /**
     * Sets the {@code PermissionFactory} instance which will be used to convert loaded
     * permission data values to {@code Permission}s. A {@code DefaultPermissionFactory}
     * will be used by default.
     */
    fun setPermissionFactory(permissionFactory: PermissionFactory) {
        this.permissionFactory = permissionFactory
    }
}
