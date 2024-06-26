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
import org.springframework.security.acls.dao.AclRepository
import org.springframework.security.acls.domain.DomainObjectPermission
import org.springframework.security.acls.domain.MongoAcl
import org.springframework.security.acls.domain.MongoSid
import org.springframework.security.acls.domain.AccessControlEntryImpl
import org.springframework.security.acls.domain.GrantedAuthoritySid
import org.springframework.security.acls.domain.PrincipalSid
import org.springframework.security.acls.jdbc.LookupStrategy
import org.springframework.security.acls.model.AclCache
import org.springframework.security.acls.model.AlreadyExistsException
import org.springframework.security.acls.model.ChildrenExistException
import org.springframework.security.acls.model.MutableAcl
import org.springframework.security.acls.model.MutableAclService
import org.springframework.security.acls.model.NotFoundException
import org.springframework.security.acls.model.ObjectIdentity
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.util.Assert
import java.util.UUID

/**
 * Provides a base MongoDB implementation of {@link MutableAclService}.
 * <p>
 * This implementation will map ACL related classes like {@link Acl}, {@link AccessControlEntry} and {@link Sid} to a
 * {@link MongoAcl} POJO class which is persisted or accessed via a MongoDB based aclRepository. This POJO will contain all
 * the ACL relevant data for a domain object in a non flat structure. Due to the non-flat structure lookups and updates
 * are relatively trivial compared to the SQL based {@link AclService} implementation.
 *
 * @author Ben Alex
 * @author Johannes Zlattinger
 * @author Roman Vottner
 * @author Soumik Kumar Saha
 * @since 4.3
 */
class MongoDBMutableAclService(
    repository: AclRepository,
    lookupStrategy: LookupStrategy,
    private val aclCache: AclCache,
) : MongoDBAclService(repository, lookupStrategy),
    MutableAclService {
    override fun createAcl(objectIdentity: ObjectIdentity): MutableAcl {
        Assert.notNull(objectIdentity, "Object Identity required")

        val availableAcl = aclRepository.findByInstanceIdAndClassName(objectIdentity.identifier, objectIdentity.type)

        if (!availableAcl.isNullOrEmpty()) {
            throw AlreadyExistsException("Object identity '$objectIdentity' already exists")
        }

        // Need to retrieve the current principal, in order to know who "owns" this ACL
        val auth: Authentication = SecurityContextHolder.getContext().authentication
        val sid = PrincipalSid(auth)

        val mongoAcl =
            MongoAcl(
                objectIdentity.identifier,
                objectIdentity.type,
                UUID.randomUUID().toString(),
                MongoSid(sid.principal),
                null,
                true,
            )

        aclRepository.save(mongoAcl)

        // Retrieve the ACL via superclass (ensures cache registration, proper retrieval etc)
        val acl = readAclById(objectIdentity)
        Assert.isInstanceOf(MutableAcl::class.java, acl, "MutableAcl should be returned")

        return acl as MutableAcl
    }

    override fun deleteAcl(
        objectIdentity: ObjectIdentity,
        deleteChildren: Boolean,
    ) {
        Assert.notNull(objectIdentity, "Object Identity required")
        Assert.notNull(objectIdentity.identifier, "Object Identity doesn't provide an identifier")

        val children = findChildren(objectIdentity)
        if (deleteChildren) {
            children?.forEach { child ->
                deleteAcl(child, true)
            }
        } else if (children!!.isNotEmpty()) {
            throw ChildrenExistException("Cannot delete '$objectIdentity' (has ${children.size} children)")
        }

        val numRemoved = aclRepository.deleteByInstanceId(objectIdentity.identifier)
        if (numRemoved == null || numRemoved < 1) {
            // TODO: log warning that no ACL was found for the domain object
        }

        // Clear the cache
        aclCache.evictFromCache(objectIdentity)
    }

    override fun updateAcl(acl: MutableAcl): MutableAcl {
        val mongoAcl =
            aclRepository
                .findById(acl.id.toString())
                .orElseThrow { NotFoundException("No entry for ACL ${acl.id} found") }

        // Clear existing ACEs in the ACL
        mongoAcl.permissions.clear()

        acl.entries.forEach { _ace ->
            val ace = _ace as AccessControlEntryImpl
            var sid: MongoSid? = null
            var aceId = ace.id as? String ?: UUID.randomUUID().toString()
            sid =
                when (ace.sid) {
                    is PrincipalSid -> {
                        val principal = ace.sid as PrincipalSid
                        MongoSid(principal.principal, true)
                    }
                    is GrantedAuthoritySid -> {
                        val grantedAuthority = ace.sid as GrantedAuthoritySid
                        MongoSid(grantedAuthority.grantedAuthority, false)
                    }
                    else -> null
                }
            val permission =
                DomainObjectPermission(
                    aceId,
                    sid!!,
                    ace.permission.mask,
                    ace.isGranting,
                    ace.isAuditSuccess,
                    ace.isAuditFailure,
                )
            mongoAcl.permissions.add(permission)
        }

        // Update the ACL entry
        aclRepository.save(mongoAcl)

        // Clear the cache, including children
        clearCacheIncludingChildren(acl.objectIdentity)

        // Retrieve the ACL via superclass (ensures cache registration, proper retrieval etc)
        return readAclById(acl.objectIdentity) as MutableAcl
    }

    private fun clearCacheIncludingChildren(objectIdentity: ObjectIdentity) {
        Assert.notNull(objectIdentity, "ObjectIdentity required")
        findChildren(objectIdentity)?.forEach { child ->
            clearCacheIncludingChildren(child)
        }
        aclCache.evictFromCache(objectIdentity)
    }
}
