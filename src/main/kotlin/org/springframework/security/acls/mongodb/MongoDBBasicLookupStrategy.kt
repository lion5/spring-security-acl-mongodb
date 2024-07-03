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
import org.springframework.security.acls.domain.AccessControlEntryImpl
import org.springframework.security.acls.domain.AclAuthorizationStrategy
import org.springframework.security.acls.domain.AclImpl
import org.springframework.security.acls.domain.AuditLogger
import org.springframework.security.acls.domain.DefaultPermissionFactory
import org.springframework.security.acls.domain.DefaultPermissionGrantingStrategy
import org.springframework.security.acls.domain.GrantedAuthoritySid
import org.springframework.security.acls.domain.MongoAcl
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
    /**
     * Spring template for interacting with a MongoDB database
     **/
    private val mongoTemplate: MongoTemplate,
    /**
     * Used to avoid further database lookups for already retrieved Acl instances
     **/
    private val aclCache: AclCache,
    /**
     * A Spring Security authorization strategy passed to the generated Acl implementation once the data are loaded from
     * the database. This strategy checks whether existing permission entries for users may be removed or new ones added.
     */
    private val aclAuthorizationStrategy: AclAuthorizationStrategy,
    /**
     * This strategy implementation will be injected into the generated Spring Security Acl class after retrieving the
     * data from the database
     **/
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
                acl?.let {
                    if (it.isSidLoaded(sids)) {
                        if (definesAccessPermissionsForSids(it, sids)) {
                            result[it.objectIdentity] = it
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
            acl?.let {
                if (definesAccessPermissionsForSids(it, sids)) {
                    resultMap[it.objectIdentity] = it
                }
            }
        }

        return resultMap
    }

    /**
     * Converts the internal MongoDB representation to a Spring Security ACL instance.
     *
     * @param mongoAcl  The internal MongoDB based data model to convert to a Spring Security ACL one
     * @param foundAcls A list of already fetched MongoDB based data model instances
     * @return The converted Spring Security ACL instance filled with values taken from the MongoDB based data model
     * @throws ClassNotFoundException If no class representation could be found for the domain object the ACL is referring
     *                                to
     */
    @Throws(ClassNotFoundException::class)
    private fun convertToAcl(
        mongoAcl: MongoAcl,
        foundAcls: MutableList<MongoAcl>,
    ): Acl? {
        var parent: Acl? = null
        mongoAcl.parentId?.let { parentId ->
            // First attempt to find the parent ACL from the already loaded ACLs
            val parentAcl =
                foundAcls.find { it.id == parentId }
                    ?: mongoTemplate.findById(parentId, MongoAcl::class.java) // Try to load it from the database if not found

            parentAcl?.let { acl ->
                // Check if the found or loaded ACL is already in the found list, if not add it
                if (!foundAcls.contains(acl)) {
                    foundAcls.add(acl)
                }

                // Attempt to retrieve a cached version of the parent ACL
                parent = aclCache.getFromCache(ObjectIdentityImpl(acl.className, acl.instanceId))
                    ?: convertToAcl(acl, foundAcls).also { newAcl ->
                        aclCache.putInCache(newAcl as MutableAcl)
                    }
            } ?: run {
                // Log warning that no parent could be found
                // TODO: Implement logging here
            }
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
     * <p>
     * This implementation will first check if the owner of the domain object is contained in the list and if not check if
     * any of the defined permissions are targeted at a security identity defined in the given list. In case a parent ACL
     * is defined, this implementation will also try to determine whether the owner of an ancestor ACL is found in the
     * given list or any of the permissions defined by an ancestor does contain identities available in the provided list.
     *
     * @param acl  The {@link Acl} instance to check whether it defines at least one of the identities provided
     * @param sids A list of security identities the ACL should be checked against whether it defines at least one of
     *             these
     * @return <em>true</em> if the given ACL specifies at least one security identity available within the given list of
     * identities. <em>false</em> if none of the passed in security identities could be found in either the provided ACL
     * or any of its ancestor permissions
     */
    private fun definesAccessPermissionsForSids(
        acl: Acl,
        sids: List<Sid>?,
    ): Boolean {
        // check whether the list of sids is a match-all list or if the owner is found within the list
        if (sids.isNullOrEmpty() || acl.owner in sids) {
            return true
        }
        // check the contained permissions for permissions granted to a certain user available in the provided list of sids
        if (hasPermissionsForSids(acl, sids)) {
            return true
        }
        // check if a parent reference is available and inheritance is enabled
        return if (acl.parentAcl != null && acl.isEntriesInheriting) {
            return if (definesAccessPermissionsForSids(acl.parentAcl, sids)) {
                true
            } else {
                hasPermissionsForSids(acl.parentAcl, sids)
            }
        } else {
            false
        }
    }

    /**
     * Checks whether the provided ACL contains permissions issued for any of the given security identities.
     *
     * @param acl  The {@link Acl} instance to check whether it contains permissions issued for any of the provided
     *             security identities
     * @param sids A list of security identities the Acl instance should be checked against if it defines permissions for
     *             any of the contained identities
     * @return <em>true</em> if the ACL defines at least one permission for a security identity available within the given
     * list of security identities. <em>false</em> if none of the permissions specified in the given Acl does define
     * access rules for any identity available in the list of security entities passed in
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
