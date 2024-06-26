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

import com.mongodb.client.MongoClient
import com.mongodb.client.MongoClients
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.cache.Cache
import org.springframework.cache.CacheManager
import org.springframework.cache.concurrent.ConcurrentMapCacheManager
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.ComponentScan
import org.springframework.context.annotation.Configuration
import org.springframework.data.mongodb.core.MongoTemplate
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories
import org.springframework.security.acls.dao.AclRepository
import org.springframework.security.acls.domain.*
import org.springframework.security.acls.jdbc.LookupStrategy
import org.springframework.security.acls.model.*
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.test.context.support.WithMockUser
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.TestExecutionListeners
import org.springframework.test.context.junit.jupiter.SpringExtension
import org.springframework.test.context.support.AnnotationConfigContextLoader
import java.net.UnknownHostException
import java.util.*
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

@ExtendWith(SpringExtension::class)
@ContextConfiguration(classes = [MongoDBMutableAclServiceTest.ContextConfig::class], loader = AnnotationConfigContextLoader::class)
@TestExecutionListeners(listeners = [MongoDBTestExecutionListener::class], mergeMode = TestExecutionListeners.MergeMode.MERGE_WITH_DEFAULTS)
class MongoDBMutableAclServiceTest {

    @ComponentScan(basePackageClasses = [MongoDBMutableAclService::class])
    @Configuration
    @EnableMongoRepositories(basePackageClasses = [AclRepository::class])
    class ContextConfig {

        @Autowired
        lateinit var aclRepository: AclRepository

        @Bean
        @Throws(UnknownHostException::class)
        fun mongoTemplate(): MongoTemplate {
            val mongoClient: MongoClient = MongoClients.create("mongodb://localhost:27017")
            return MongoTemplate(mongoClient, "spring-security-acl-test")
        }

        @Bean
        fun aclAuthorizationStrategy(): AclAuthorizationStrategy = AclAuthorizationStrategyImpl(SimpleGrantedAuthority("ROLE_ADMINISTRATOR"))

        @Bean
        fun permissionGrantingStrategy(): PermissionGrantingStrategy = DefaultPermissionGrantingStrategy(ConsoleAuditLogger())

        @Bean
        @Throws(UnknownHostException::class)
        fun lookupStrategy(): LookupStrategy = MongoDBBasicLookupStrategy(mongoTemplate(), aclCache(), aclAuthorizationStrategy(), permissionGrantingStrategy())

        @Bean
        fun cacheManager(): CacheManager = ConcurrentMapCacheManager("test")

        @Bean
        fun aclCache(): AclCache {
            val springCache: Cache = cacheManager().getCache("test")!!
            return SpringCacheBasedAclCache(springCache, permissionGrantingStrategy(), aclAuthorizationStrategy())
        }

        @Bean
        @Throws(UnknownHostException::class)
        fun aclService(): MongoDBMutableAclService = MongoDBMutableAclService(aclRepository, lookupStrategy(), aclCache())
    }

    @Autowired
    lateinit var aclService: MongoDBMutableAclService
    @Autowired
    lateinit var aclRepository: AclRepository

    @AfterEach
    fun cleanup() {
        aclRepository.findAll().forEach { acl -> aclRepository.delete(acl) }
    }

    @Test
    @WithMockUser
    fun testCreateAcl() {
        // Arrange
        val domainObject = TestDomainObject()
        val objectIdentity = ObjectIdentityImpl(domainObject::class.java.name, domainObject.getId())

        // Act
        val acl = aclService.createAcl(objectIdentity)

        // Assert
        assertNotNull(acl)
        assertTrue(acl.objectIdentity.identifier == domainObject.getId())
        assertTrue(acl.objectIdentity.type == domainObject::class.java.name)
        assertTrue(acl.owner == PrincipalSid(SecurityContextHolder.getContext().authentication.name))
    }

    @Test
    @WithMockUser
    fun testDeleteAcl() {
        // Arrange
        val domainObject = TestDomainObject()
        val objectIdentity = ObjectIdentityImpl(domainObject::class.java.name, domainObject.getId())
        val mongoAcl = MongoAcl(domainObject.getId(), domainObject::class.java.name,
            UUID.randomUUID().toString(), MongoSid(SecurityContextHolder.getContext().authentication.name),
            null, true)
        val permission = DomainObjectPermission(UUID.randomUUID().toString(),
            MongoSid(SecurityContextHolder.getContext().authentication.name),
            BasePermission.READ.mask or BasePermission.WRITE.mask,
            true, true, true)
        mongoAcl.permissions.add(permission)
        aclRepository.save(mongoAcl)

        // Act
        aclService.deleteAcl(objectIdentity, true)

        // Assert
        val afterDelete = aclRepository.findById(mongoAcl.id!!).orElse(null)
        assertNull(afterDelete)
    }

    @Test
    @WithMockUser
    fun testDeleteAcl_includingChildren() {
        // Arrange
        val domainObject = TestDomainObject()
        val firstObject = TestDomainObject()
        val secondObject = TestDomainObject()
        val thirdObject = TestDomainObject()
        val unrelatedObject = TestDomainObject()

        val objectIdentity = ObjectIdentityImpl(domainObject::class.java.name, domainObject.getId())
        val parent = MongoAcl(domainObject.getId(), domainObject::class.java.name, UUID.randomUUID().toString())
        val child1 = MongoAcl(firstObject.getId(), firstObject::class.java.name, UUID.randomUUID().toString(), MongoSid("Tim Test"), parent.id, true)
        val child2 = MongoAcl(secondObject.getId(), secondObject::class.java.name, UUID.randomUUID().toString(), MongoSid("Petty Pattern"), parent.id, true)
        val child3 = MongoAcl(thirdObject.getId(), thirdObject::class.java.name, UUID.randomUUID().toString(), MongoSid("Sam Sample"), parent.id, true)
        val nonChild = MongoAcl(unrelatedObject.getId(), unrelatedObject::class.java.name, UUID.randomUUID().toString())

        val permission = DomainObjectPermission(UUID.randomUUID().toString(),
            MongoSid(SecurityContextHolder.getContext().authentication.name),
            BasePermission.READ.mask or BasePermission.WRITE.mask,
            true, true, true)

        parent.permissions.add(permission)
        child1.permissions.add(permission)
        child2.permissions.add(permission)
        aclRepository.save(parent)
        aclRepository.save(child1)
        aclRepository.save(child2)
        aclRepository.save(child3)
        aclRepository.save(nonChild)

        // Act
        aclService.deleteAcl(objectIdentity, true)

        // Assert
        val afterDelete = aclRepository.findById(parent.id!!).orElse(null)
        assertNull(afterDelete)
        val remaining = aclRepository.findAll()
        assertTrue(remaining.size == 1)
        assertTrue(remaining[0].id == nonChild.id)
    }

    @Test
    @WithMockUser
    fun testDeleteAcl_excludingChildren() {
        // Arrange
        val domainObject = TestDomainObject()
        val firstObject = TestDomainObject()
        val secondObject = TestDomainObject()
        val thirdObject = TestDomainObject()
        val unrelatedObject = TestDomainObject()

        val objectIdentity = ObjectIdentityImpl(domainObject::class.java.name, domainObject.getId())
        val parent = MongoAcl(domainObject.getId(), domainObject::class.java.name, UUID.randomUUID().toString())
        val child1 = MongoAcl(firstObject.getId(), firstObject::class.java.name, UUID.randomUUID().toString(), MongoSid("Tim Test"), parent.id, true)
        val child2 = MongoAcl(secondObject.getId(), secondObject::class.java.name, UUID.randomUUID().toString(), MongoSid("Petty Pattern"), parent.id, true)
        val child3 = MongoAcl(thirdObject.getId(), thirdObject::class.java.name, UUID.randomUUID().toString(), MongoSid("Sam Sample"), parent.id, true)
        val nonChild = MongoAcl(unrelatedObject.getId(), unrelatedObject::class.java.name, UUID.randomUUID().toString())

        val permission = DomainObjectPermission(UUID.randomUUID().toString(),
            MongoSid(SecurityContextHolder.getContext().authentication.name),
            BasePermission.READ.mask or BasePermission.WRITE.mask,
            true, true, true)

        parent.permissions.add(permission)
        child1.permissions.add(permission)
        child2.permissions.add(permission)
        aclRepository.save(parent)
        aclRepository.save(child1)
        aclRepository.save(child2)
        aclRepository.save(child3)
        aclRepository.save(nonChild)

        // Act
        try {
            aclService.deleteAcl(objectIdentity, false)
            fail("Should have thrown an exception as removing a parent ACL is not allowed")
        } catch (ex: ChildrenExistException) {
            assertNotNull(ex)
        }
    }

    @Test
    @WithMockUser
    fun testUpdateAcl() {
        // Arrange
        val domainObject = TestDomainObject()
        val objectIdentity = ObjectIdentityImpl(domainObject::class.java.name, domainObject.getId())
        val mongoAcl = MongoAcl(domainObject.getId(), domainObject::class.java.name,
            UUID.randomUUID().toString(), MongoSid(SecurityContextHolder.getContext().authentication.name),
            null, true)
        val permission = DomainObjectPermission(UUID.randomUUID().toString(),
            MongoSid(SecurityContextHolder.getContext().authentication.name),
            BasePermission.READ.mask or BasePermission.WRITE.mask,
            true, true, true)
        mongoAcl.permissions.add(permission)
        aclRepository.save(mongoAcl)

        val updatedAcl = aclService.readAclById(objectIdentity) as MutableAcl
        updatedAcl.insertAce(updatedAcl.entries.size, BasePermission.ADMINISTRATION, PrincipalSid("Sam Sample"), true)

        // Act
        aclService.updateAcl(updatedAcl)

        // Assert
        val updated = aclRepository.findById(mongoAcl.id!!).orElse(null)
        assertNotNull(updated)
        assertTrue(updated!!.permissions.size == 2)
        assertTrue(updated.permissions[0].getId() == permission.getId())
        assertTrue(updated.permissions[1].getPermission() == BasePermission.ADMINISTRATION.mask)
        assertTrue(updated.permissions[1].getSid().name == "Sam Sample")
        assertTrue(updated.permissions[1].getSid().isPrincipal)
    }

}
