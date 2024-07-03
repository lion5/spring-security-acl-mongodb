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

import com.mongodb.client.MongoClients
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.testcontainers.context.ImportTestcontainers
import org.springframework.boot.testcontainers.service.connection.ServiceConnection
import org.springframework.cache.CacheManager
import org.springframework.cache.concurrent.ConcurrentMapCacheManager
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.ComponentScan
import org.springframework.context.annotation.Configuration
import org.springframework.data.mongodb.core.MongoTemplate
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories
import org.springframework.security.acls.dao.AclRepository
import org.springframework.security.acls.domain.AclAuthorizationStrategy
import org.springframework.security.acls.domain.AclAuthorizationStrategyImpl
import org.springframework.security.acls.domain.BasePermission
import org.springframework.security.acls.domain.ConsoleAuditLogger
import org.springframework.security.acls.domain.DefaultPermissionGrantingStrategy
import org.springframework.security.acls.domain.DomainObjectPermission
import org.springframework.security.acls.domain.MongoAcl
import org.springframework.security.acls.domain.MongoSid
import org.springframework.security.acls.domain.ObjectIdentityImpl
import org.springframework.security.acls.domain.PrincipalSid
import org.springframework.security.acls.domain.SpringCacheBasedAclCache
import org.springframework.security.acls.jdbc.LookupStrategy
import org.springframework.security.acls.model.AccessControlEntry
import org.springframework.security.acls.model.Acl
import org.springframework.security.acls.model.AclCache
import org.springframework.security.acls.model.AclService
import org.springframework.security.acls.model.NotFoundException
import org.springframework.security.acls.model.ObjectIdentity
import org.springframework.security.acls.model.PermissionGrantingStrategy
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.test.context.support.WithMockUser
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension
import org.testcontainers.containers.MongoDBContainer
import java.util.UUID
import java.util.function.Consumer
import kotlin.test.fail

/**
 * Contains tests for retrieving ACLs via a {@link MongoDBAclService} instance.
 *
 * @author Roman Vottner
 * @author Soumik Kumar Saha
 * @since 4.3
 */
@ExtendWith(SpringExtension::class)
@ContextConfiguration(classes = [MongoDBAclServiceTest.ContextConfig::class])
class MongoDBAclServiceTest {
    /**
     * Sample Spring configuration for using ACLs stored in a MongoDB
     */
    @ImportTestcontainers
    @ComponentScan(basePackageClasses = [AclRepository::class])
    @Configuration
    @EnableMongoRepositories(basePackageClasses = [AclRepository::class])
    class ContextConfig {
        companion object {
            @ServiceConnection
            @JvmStatic
            val mongoDBContainer = MongoDBContainer("mongo:7.0.11")
        }

        @Bean
        fun mongoTemplate(): MongoTemplate {
            val mongoClient = MongoClients.create(mongoDBContainer.connectionString)
            return MongoTemplate(mongoClient, "spring-security-acl-test")
        }

        @Bean
        fun aclAuthorizationStrategy(): AclAuthorizationStrategy =
            AclAuthorizationStrategyImpl(SimpleGrantedAuthority("ROLE_ADMINISTRATOR"))

        @Bean
        fun permissionGrantingStrategy(): PermissionGrantingStrategy = DefaultPermissionGrantingStrategy(ConsoleAuditLogger())

        @Bean
        fun lookupStrategy(
            mongoTemplate: MongoTemplate,
            aclCache: AclCache,
            aclAuthorizationStrategy: AclAuthorizationStrategy,
            permissionGrantingStrategy: PermissionGrantingStrategy,
        ): LookupStrategy = MongoDBBasicLookupStrategy(mongoTemplate, aclCache, aclAuthorizationStrategy, permissionGrantingStrategy)

        @Bean
        fun cacheManager(): CacheManager = ConcurrentMapCacheManager("test")

        @Bean
        fun aclCache(cacheManager: CacheManager): AclCache {
            val springCache = cacheManager.getCache("test")!!
            return SpringCacheBasedAclCache(springCache, permissionGrantingStrategy(), aclAuthorizationStrategy())
        }

        @Bean
        fun aclService(
            aclRepository: AclRepository,
            lookupStrategy: LookupStrategy,
        ): AclService = MongoDBAclService(aclRepository, lookupStrategy)
    }

    @Autowired
    private lateinit var aclService: AclService

    @Autowired
    private lateinit var mongoTemplate: MongoTemplate

    @Autowired
    private lateinit var aclRepository: AclRepository

    /**
     * Tests the retrieval of child domain objects by providing a representation of the parent domain object holder.
     * Note the current implementation does filter duplicate children.
     */
    @Test
    @WithMockUser
    fun testFindChildren() {
        // Arrange
        val domainObject = TestDomainObject()
        val child1DomainObject = TestDomainObject()
        val child2DomainObject = TestDomainObject()
        val otherDomainObject = TestDomainObject()
        val unrelatedDomainObject = TestDomainObject()

        val parent = MongoAcl(domainObject.getId(), domainObject::class.java.name, UUID.randomUUID().toString())
        val child1 =
            MongoAcl(
                child1DomainObject.getId(),
                child1DomainObject::class.java.name,
                UUID.randomUUID().toString(),
                MongoSid("Tim Test"),
                parent.id,
                true,
            )
        val child2 =
            MongoAcl(
                child2DomainObject.getId(),
                child2DomainObject::class.java.name,
                UUID.randomUUID().toString(),
                MongoSid("Petty Pattern"),
                parent.id,
                true,
            )
        val child3 =
            MongoAcl(
                otherDomainObject.getId(),
                otherDomainObject::class.java.name,
                UUID.randomUUID().toString(),
                MongoSid("Sam Sample"),
                parent.id,
                true,
            )
        val nonChild = MongoAcl(unrelatedDomainObject.getId(), unrelatedDomainObject::class.java.name, UUID.randomUUID().toString())

        mongoTemplate.save(parent)
        mongoTemplate.save(child1)
        mongoTemplate.save(child2)
        mongoTemplate.save(child3)
        mongoTemplate.save(nonChild)

        // Act
        val parentIdentity = ObjectIdentityImpl(parent.className, parent.instanceId)
        val children = aclService.findChildren(parentIdentity)

        // Assert
        assert(children.size == 3)
        assert(children[0].identifier == child1DomainObject.getId())
        assert(children[0].type == child1DomainObject::class.java.name)
        assert(children[1].identifier == child2DomainObject.getId())
        assert(children[1].type == child2DomainObject::class.java.name)
        assert(children[2].identifier == otherDomainObject.getId())
        assert(children[2].type == otherDomainObject::class.java.name)
    }

    /**
     * This test assumes that ACLs can be retrieved via {@link AclService#readAclById(ObjectIdentity)} method.
     *
     * @throws Exception any exception thrown during the test are propagated further. No exception handling is done in
     *                   the test
     */
    @Test
    @WithMockUser
    fun testReadAclById() {
        // Arrange
        val readWritePermissions = BasePermission.READ.mask or BasePermission.WRITE.mask
        val readWriteCreatePermissions = BasePermission.READ.mask or BasePermission.WRITE.mask or BasePermission.CREATE.mask

        val parentObject = TestDomainObject()
        val domainObject = TestDomainObject()

        val parentAcl =
            MongoAcl(
                parentObject.getId(),
                parentObject::class.java.name,
                UUID.randomUUID().toString(),
                MongoSid("Check Norris"),
                null,
                true,
            )
        val mongoAcl =
            MongoAcl(
                domainObject.getId(),
                domainObject::class.java.name,
                UUID.randomUUID().toString(),
                MongoSid("Petty Pattern"),
                parentAcl.id,
                true,
            )
        val permissions =
            mutableListOf(
                DomainObjectPermission(UUID.randomUUID().toString(), MongoSid("Sam Sample"), readWritePermissions, true, false, true),
                DomainObjectPermission(UUID.randomUUID().toString(), MongoSid("Tim Test"), readWriteCreatePermissions, true, false, true),
            )
        mongoAcl.permissions = permissions

        mongoTemplate.save(parentAcl)
        mongoTemplate.save(mongoAcl)

        // Act
        val parentIdentity = ObjectIdentityImpl(parentAcl.className, parentAcl.instanceId)
        val objectIdentity = ObjectIdentityImpl(mongoAcl.className, mongoAcl.instanceId)
        val pAcl = aclService.readAclById(parentIdentity)
        val acl = aclService.readAclById(objectIdentity)

        // Assert
        assertEquals(acl.objectIdentity.identifier, domainObject.getId())
        assertEquals(acl.objectIdentity.type, domainObject::class.java.name)
        assertEquals(acl.parentAcl, pAcl)
        assertEquals(acl.entries.size, 2)
        assertEquals(acl.entries[0].sid, PrincipalSid("Sam Sample"))
        assertEquals(acl.entries[0].permission.mask, readWritePermissions)
        assertEquals(acl.owner, PrincipalSid("Petty Pattern"))
        assertTrue(acl.isEntriesInheriting)
    }

    @Test
    @WithMockUser
    fun testReadAclsById_ForSpecifiedSids() {
        // Arrange
        val domainObject = TestDomainObject()
        val firstObject = TestDomainObject()
        val secondObject = TestDomainObject()
        val thirdObject = TestDomainObject()
        val unrelatedObject = TestDomainObject()

        val parent =
            MongoAcl(
                domainObject.getId(),
                domainObject::class.java.name,
                UUID.randomUUID().toString(),
            )
        val child1 =
            MongoAcl(
                firstObject.getId(),
                firstObject::class.java.name,
                UUID.randomUUID().toString(),
                MongoSid("Tim Test"),
                parent.id,
                true,
            )
        val child2 =
            MongoAcl(
                secondObject.getId(),
                secondObject::class.java.name,
                UUID.randomUUID().toString(),
                MongoSid("Petty Pattern"),
                parent.id,
                true,
            )
        val child3 =
            MongoAcl(
                thirdObject.getId(),
                thirdObject::class.java.name,
                UUID.randomUUID().toString(),
                MongoSid("Sam Sample"),
                parent.id,
                true,
            )
        val nonChild =
            MongoAcl(
                unrelatedObject.getId(),
                unrelatedObject::class.java.name,
                UUID.randomUUID().toString(),
            )

        val permission =
            DomainObjectPermission(
                UUID.randomUUID().toString(),
                MongoSid(SecurityContextHolder.getContext().authentication.name),
                BasePermission.READ.mask or BasePermission.WRITE.mask,
                true,
                true,
                true,
            )

        parent.permissions.add(permission)
        child1.permissions.add(permission)
        child2.permissions.add(permission)

        aclRepository.save(parent)
        aclRepository.save(child1)
        aclRepository.save(child2)
        aclRepository.save(child3)
        aclRepository.save(nonChild)

        // Act
        val sids = listOf(PrincipalSid("Tim Test"), PrincipalSid("Sam Sample"))

        val parentIdentity: ObjectIdentity =
            ObjectIdentityImpl(Class.forName(domainObject.javaClass.name), domainObject.getId())
        val firstObjectIdentity: ObjectIdentity =
            ObjectIdentityImpl(Class.forName(firstObject.javaClass.name), firstObject.getId())
        val secondObjectIdentity: ObjectIdentity =
            ObjectIdentityImpl(Class.forName(secondObject.javaClass.name), secondObject.getId())
        val thirdObjectIdentity: ObjectIdentity =
            ObjectIdentityImpl(Class.forName(thirdObject.javaClass.name), thirdObject.getId())

        // Quote from AclService's Javadoc:
        //     "The returned map is keyed on the passed objects, with the values being the <tt>Acl</tt> instances. Any
        //      unknown objects (or objects for which the interested <tt>Sid</tt>s do not have entries) will not have a
        //      map key."
        // The verification in AclService though throws a NotFoundException if an ACL for a given ObjectIdentity could
        // not be obtained!

        // neither the parent ...
        try {
            aclService.readAclsById(listOf(parentIdentity), sids)
            fail(
                "Should have thrown a NotFoundException as no ACL should be obtainable as the parent ACL does not define permissions for any identity provided in the given list",
            )
        } catch (ex: Exception) {
            assertThrows<NotFoundException> { throw ex }
        }
        // ... nor a sibling which do not specify any of the provided sids in the permissions (or owner) shall be obtainable
        try {
            aclService.readAclsById(listOf(firstObjectIdentity, secondObjectIdentity, thirdObjectIdentity), sids)
            fail(
                "Should have thrown a NotFoundException as no ACL should be obtainable for the second object identity passed in due to not specifying any of the provided security identities",
            )
        } catch (ex: Exception) {
            assertThrows<NotFoundException> { throw ex }
        }

        val acl: Map<ObjectIdentity, Acl> = aclService.readAclsById(listOf(firstObjectIdentity, thirdObjectIdentity), sids)

        // Assert
        assertTrue(acl.keys.containsAll(listOf(firstObjectIdentity, thirdObjectIdentity)) && acl.keys.size == 2)
    }

    /**
     * This test assumes that ACLs inherit the permission of the parent ACL if inheritance is configured on the child.
     *
     * @throws Exception any unexpected exception are propagated further
     */
    @Test
    @WithMockUser
    fun testReadAclsById_checkChildAclIsInheritingPermissions() {
        // Arrange
        val domainObject = TestDomainObject()
        val firstObject = TestDomainObject()
        val secondObject = TestDomainObject()
        val thirdObject = TestDomainObject()
        val unrelatedObject = TestDomainObject()

        val objectIdentity: ObjectIdentity =
            ObjectIdentityImpl(Class.forName(domainObject.javaClass.name), domainObject.getId())

        val parent = MongoAcl(domainObject.getId(), domainObject::class.java.name, UUID.randomUUID().toString())
        val child1 =
            MongoAcl(
                firstObject.getId(),
                firstObject::class.java.name,
                UUID.randomUUID().toString(),
                MongoSid("Tim Test"),
                parent.id,
                true,
            )
        val child2 =
            MongoAcl(
                secondObject.getId(),
                secondObject::class.java.name,
                UUID.randomUUID().toString(),
                MongoSid("Petty Pattern"),
                parent.id,
                true,
            )
        val child3 =
            MongoAcl(
                thirdObject.getId(),
                thirdObject::class.java.name,
                UUID.randomUUID().toString(),
                MongoSid("Sam Sample"),
                parent.id,
                true,
            )
        val nonChild = MongoAcl(unrelatedObject.getId(), unrelatedObject::class.java.name, UUID.randomUUID().toString())

        val permission =
            DomainObjectPermission(
                UUID.randomUUID().toString(),
                MongoSid(SecurityContextHolder.getContext().authentication.name),
                BasePermission.READ.mask or BasePermission.WRITE.mask,
                true,
                true,
                true,
            )
        parent.permissions.add(permission)
        child1.permissions.add(permission)
        child2.permissions.add(permission)

        aclRepository.save(parent)
        aclRepository.save(child1)
        aclRepository.save(child2)
        aclRepository.save(child3)
        aclRepository.save(nonChild)

        // Act
        val sids = listOf(PrincipalSid(SecurityContextHolder.getContext().authentication.name), PrincipalSid("Tim Test"))
        val childObjects = aclService.findChildren(objectIdentity)
        val resultUser = aclService.readAclsById(childObjects, sids)

        // Assert
        // The default constructor on the parent ACL sets the owner to the authenticated user by default though the
        // parent also specifies permission for the current user explicitly. As permissions are looked up on ancestors
        // in case `entriesInheriting` is set to true, the 3rd child is also retrieved here as well
        assertTrue(resultUser.keys.size == 3)
    }

    /**
     * This test assumes that inherited ACLs are complete.
     *
     * @throws Exception any unexpected exception are propagated further
     */
    @Test
    @WithMockUser
    fun testReadAclsById_checkAclContainsProperInheritanceStructure() {
        // Arrange
        val domainObject = TestDomainObject()
        val firstObject = TestDomainObject()
        val secondObject = TestDomainObject()
        val thirdObject = TestDomainObject()
        val unrelatedObject = TestDomainObject()

        val objectIdentity = ObjectIdentityImpl(domainObject::class.java.name, domainObject.getId())

        val parent =
            MongoAcl(domainObject.getId(), domainObject::class.java.name, UUID.randomUUID().toString(), MongoSid("owner"), null, true)
        val child1 =
            MongoAcl(firstObject.getId(), firstObject::class.java.name, UUID.randomUUID().toString(), MongoSid("Tim Test"), parent.id, true)
        val child2 =
            MongoAcl(
                secondObject.getId(),
                secondObject::class.java.name,
                UUID.randomUUID().toString(),
                MongoSid("Petty Pattern"),
                parent.id,
                true,
            )
        val child3 =
            MongoAcl(
                thirdObject.getId(),
                thirdObject::class.java.name,
                UUID.randomUUID().toString(),
                MongoSid("Sam Sample"),
                parent.id,
                true,
            )
        val nonChild = MongoAcl(unrelatedObject.getId(), unrelatedObject::class.java.name, UUID.randomUUID().toString())

        val permission =
            DomainObjectPermission(
                UUID.randomUUID().toString(),
                MongoSid(SecurityContextHolder.getContext().authentication.name),
                BasePermission.READ.mask or BasePermission.WRITE.mask,
                granting = true,
                auditSuccess = true,
                auditFailure = true,
            )
        parent.permissions.add(permission)
        child1.permissions.add(permission)
        child2.permissions.add(permission)

        aclRepository.save(parent)
        aclRepository.save(child1)
        aclRepository.save(child2)
        aclRepository.save(child3)
        aclRepository.save(nonChild)

        // Act
        val sids = listOf(PrincipalSid(SecurityContextHolder.getContext().authentication.name))

        val childObjects = aclService.findChildren(objectIdentity)
        val resultUser = aclService.readAclsById(childObjects, sids)

        // Assert
        assertTrue(childObjects.size == 3)
        assertTrue(resultUser.keys.size == 3)

        // permissions for the 3rd child are inherited from its parent though not copied to the child directly! A
        // permission evaluator therefore has to check whether isEntriesInheriting is true and check the ancestors for
        // permissions as well
        resultUser.keys.forEach(
            Consumer { objectIdentity1: Any? ->
                val acl = resultUser[objectIdentity1]
                checkPermissions(acl!!)
            },
        )
    }

    @Test
    @WithMockUser
    fun issue3_testReadAclsByIdTwice() {
        // Arrange
        val domainObject = TestDomainObject()
        val firstObject = TestDomainObject()
        val secondObject = TestDomainObject()
        val thirdObject = TestDomainObject()
        val unrelatedObject = TestDomainObject()

        val objectIdentity: ObjectIdentity =
            ObjectIdentityImpl(Class.forName(domainObject.javaClass.name), domainObject.getId())

        val parent =
            MongoAcl(domainObject.getId(), domainObject::class.java.name, UUID.randomUUID().toString(), MongoSid("owner"), null, true)
        val child1 =
            MongoAcl(firstObject.getId(), firstObject::class.java.name, UUID.randomUUID().toString(), MongoSid("Tim Test"), parent.id, true)
        val child2 =
            MongoAcl(
                secondObject.getId(),
                secondObject::class.java.name,
                UUID.randomUUID().toString(),
                MongoSid("Petty Pattern"),
                parent.id,
                true,
            )
        val child3 =
            MongoAcl(
                thirdObject.getId(),
                thirdObject::class.java.name,
                UUID.randomUUID().toString(),
                MongoSid("Sam Sample"),
                parent.id,
                true,
            )
        val nonChild = MongoAcl(unrelatedObject.getId(), unrelatedObject::class.java.name, UUID.randomUUID().toString())

        val user0Permissions =
            DomainObjectPermission(
                UUID.randomUUID().toString(),
                MongoSid("user-0"),
                BasePermission.READ.mask or BasePermission.WRITE.mask,
                true,
                true,
                true,
            )
        val user1Permissions =
            DomainObjectPermission(
                UUID.randomUUID().toString(),
                MongoSid("user-1"),
                BasePermission.READ.mask or BasePermission.WRITE.mask,
                true,
                true,
                true,
            )

        // child3 inherits permission of parent
        parent.permissions.add(user0Permissions)
        child1.permissions.add(user0Permissions)
        child2.permissions.add(user0Permissions)

        // child3 has no permission to inherit from
        child1.permissions.add(user1Permissions)
        child2.permissions.add(user1Permissions)

        aclRepository.save(parent)
        aclRepository.save(child1)
        aclRepository.save(child2)
        aclRepository.save(child3)
        aclRepository.save(nonChild)

        // Act
        val sids = listOf(PrincipalSid("owner"))
        val sids1 = listOf(PrincipalSid("user-0"))
        val sids2 = listOf(PrincipalSid("user-1"))

        val childObjects = aclService.findChildren(objectIdentity)

        val resultOwner = aclService.readAclsById(childObjects, sids)
        val resultUser = aclService.readAclsById(childObjects, sids1)

        try {
            aclService.readAclsById(childObjects, sids2)
            fail("Method should have thrown a NotFoundException as child3 ACL does not define any permissions for user-1")
        } catch (ex: Exception) {
            assertThrows<NotFoundException> { throw ex }
        }

        // Assert
        assertEquals(3, resultOwner.size)
        assertEquals(3, resultUser.keys.size)
        resultUser.keys.forEach {
            val acl = resultUser[it]
            checkPermissions(acl!!)
        }
        assertTrue(resultUser.keys.size == 3)
        assertEquals(resultOwner, resultUser)
    }

    private fun checkPermissions(acl: Acl) {
        val permissions = mutableSetOf<AccessControlEntry>()
        var parentAcl = acl.parentAcl
        if (acl.isEntriesInheriting) {
            while (parentAcl != null) {
                permissions.addAll(parentAcl.entries)
                if (!parentAcl.isEntriesInheriting) {
                    break
                }
                parentAcl = parentAcl.parentAcl
            }
        }

        assertEquals(1, permissions.size, "ACE $acl did not contain or inherit the correct permissions")
    }
}
