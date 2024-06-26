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

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.security.acls.dao.AclRepository
import org.springframework.security.acls.domain.MongoAcl
import org.springframework.security.acls.domain.ObjectIdentityImpl
import org.springframework.security.acls.jdbc.LookupStrategy
import org.springframework.security.acls.model.Acl
import org.springframework.security.acls.model.AclService
import org.springframework.security.acls.model.NotFoundException
import org.springframework.security.acls.model.ObjectIdentity
import org.springframework.security.acls.model.Sid
import org.springframework.util.Assert
import java.lang.invoke.MethodHandles

/**
 * Simple MongoDB-based implementation of {@link AclService}.
 * <p>
 * This implementation differs from the SQL based implementation by having a single MongoDB collection containing all
 * the necessary ACL related data per document in a non-final structure represented by the {@link MongoAcl} POJO. This
 * service will convert database results from POJO to ACL related classes like {@link Acl}, {@link ObjectIdentity},
 * {@link Sid} and {@link AccessControlEntry} instances internally.
 *
 * @author Ben Alex
 * @author Roman Vottner
 * @author Soumik Kumar Saha
 * @since 4.3
 */
open class MongoDBAclService(
    val aclRepository: AclRepository,
    private val lookupStrategy: LookupStrategy,
) : AclService {
    companion object {
        private val LOG: Logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass())
    }

    init {
        Assert.notNull(aclRepository, "AclRepository required")
        Assert.notNull(lookupStrategy, "LookupStrategy required")
    }

    override fun findChildren(parentIdentity: ObjectIdentity): List<ObjectIdentity>? {
        val aclsForDomainObject =
            aclRepository.findByInstanceIdAndClassName(
                parentIdentity.identifier,
                parentIdentity.type,
            ) ?: return null

        val children = LinkedHashSet<MongoAcl>()
        aclsForDomainObject.forEach { acl ->
            children.addAll(aclRepository.findByParentId(acl.id!!))
        }

        val foundChildren = mutableListOf<ObjectIdentity>()
        children.forEach { child ->
            try {
                val oId = ObjectIdentityImpl(Class.forName(child.className), child.instanceId)
                if (oId !in foundChildren) {
                    foundChildren.add(oId)
                }
            } catch (cnfEx: ClassNotFoundException) {
                LOG.error("Could not find class of domain object '{}' referenced by ACL {}", child.className, child.id)
            }
        }
        return foundChildren
    }

    override fun readAclById(objectIdentity: ObjectIdentity): Acl = readAclById(objectIdentity, null)

    override fun readAclById(
        objectIdentity: ObjectIdentity,
        sids: List<Sid>?,
    ): Acl {
        val map = readAclsById(listOf(objectIdentity), sids)
        return map[objectIdentity] ?: throw NotFoundException(
            "There should have been an Acl entry for ObjectIdentity $objectIdentity",
        )
    }

    override fun readAclsById(objects: List<ObjectIdentity>): Map<ObjectIdentity, Acl> = readAclsById(objects, null)

    override fun readAclsById(
        objects: List<ObjectIdentity>,
        sids: List<Sid>?,
    ): Map<ObjectIdentity, Acl> {
        val result = lookupStrategy.readAclsById(objects, sids)

        objects.forEach { oid ->
            result[oid] ?: throw NotFoundException(
                "Unable to find ACL information for object identity '$oid'",
            )
        }

        return result
    }
}
