package org.springframework.security.acls.mongodb

import com.mongodb.client.MongoClients
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
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
import org.springframework.security.acls.model.AclCache
import org.springframework.security.acls.model.AclService
import org.springframework.security.acls.model.NotFoundException
import org.springframework.security.acls.model.PermissionGrantingStrategy
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.test.context.support.WithMockUser
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension
import java.util.UUID

@ExtendWith(SpringExtension::class)
@ContextConfiguration(classes = [MongoDBAclServiceTest.ContextConfig::class])
class MongoDBAclServiceTest {

    @ComponentScan(basePackageClasses = [AclRepository::class])
    @Configuration
    @EnableMongoRepositories(basePackageClasses = [AclRepository::class])
    class ContextConfig {

        @Bean
        fun mongoTemplate(): MongoTemplate {
            val mongoClient = MongoClients.create("mongodb://localhost:27017")
            return MongoTemplate(mongoClient, "spring-security-acl-test")
        }

        @Bean
        fun aclAuthorizationStrategy(): AclAuthorizationStrategy =
            AclAuthorizationStrategyImpl(SimpleGrantedAuthority("ROLE_ADMINISTRATOR"))

        @Bean
        fun permissionGrantingStrategy(): PermissionGrantingStrategy =
            DefaultPermissionGrantingStrategy(ConsoleAuditLogger())

        @Bean
        fun lookupStrategy(mongoTemplate: MongoTemplate, aclCache: AclCache,
                           aclAuthorizationStrategy: AclAuthorizationStrategy,
                           permissionGrantingStrategy: PermissionGrantingStrategy): LookupStrategy =
            MongoDBBasicLookupStrategy(mongoTemplate, aclCache, aclAuthorizationStrategy, permissionGrantingStrategy)

        @Bean
        fun cacheManager(): CacheManager = ConcurrentMapCacheManager("test")

        @Bean
        fun aclCache(cacheManager: CacheManager): AclCache {
            val springCache = cacheManager.getCache("test")!!
            return SpringCacheBasedAclCache(springCache, permissionGrantingStrategy(), aclAuthorizationStrategy())
        }

        @Bean
        fun aclService(aclRepository: AclRepository, lookupStrategy: LookupStrategy): AclService =
            MongoDBAclService(aclRepository, lookupStrategy)
    }

    @Autowired
    private lateinit var aclService: AclService
    @Autowired
    private lateinit var mongoTemplate: MongoTemplate
    @Autowired
    private lateinit var aclRepository: AclRepository

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
        val child1 = MongoAcl(child1DomainObject.getId(), child1DomainObject::class.java.name, UUID.randomUUID().toString(), MongoSid("Tim Test"), parent.id, true)
        val child2 = MongoAcl(child2DomainObject.getId(), child2DomainObject::class.java.name, UUID.randomUUID().toString(), MongoSid("Petty Pattern"), parent.id, true)
        val child3 = MongoAcl(otherDomainObject.getId(), otherDomainObject::class.java.name, UUID.randomUUID().toString(), MongoSid("Sam Sample"), parent.id, true)
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

    @Test
    @WithMockUser
    fun testReadAclById() {
        // Arrange
        val readWritePermissions = BasePermission.READ.mask or BasePermission.WRITE.mask
        val readWriteCreatePermissions = BasePermission.READ.mask or BasePermission.WRITE.mask or BasePermission.CREATE.mask

        val parentObject = TestDomainObject()
        val domainObject = TestDomainObject()

        val parentAcl = MongoAcl(parentObject.getId(), parentObject::class.java.name, UUID.randomUUID().toString(), MongoSid("Check Norris"), null, true)
        val mongoAcl = MongoAcl(domainObject.getId(), domainObject::class.java.name, UUID.randomUUID().toString(), MongoSid("Petty Pattern"), parentAcl.id, true)
        val permissions = mutableListOf(
            DomainObjectPermission(UUID.randomUUID().toString(), MongoSid("Sam Sample"), readWritePermissions, true, false, true),
            DomainObjectPermission(UUID.randomUUID().toString(), MongoSid("Tim Test"), readWriteCreatePermissions, true, false, true)
        )
        mongoAcl.permissions = permissions

        aclRepository.save(parentAcl)
        aclRepository.save(mongoAcl)

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
        assertEquals(acl.entries[0].sid , PrincipalSid("Sam Sample"))
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

        val parent = MongoAcl(domainObject.getId(), domainObject::class.java.name, UUID.randomUUID().toString())
        val child1 = MongoAcl(firstObject.getId(), firstObject::class.java.name, UUID.randomUUID().toString(), MongoSid("Tim Test"), parent.id, true)
        val child2 = MongoAcl(secondObject.getId(), secondObject::class.java.name, UUID.randomUUID().toString(), MongoSid("Petty Pattern"), parent.id, true)
        val child3 = MongoAcl(thirdObject.getId(), thirdObject::class.java.name, UUID.randomUUID().toString(), MongoSid("Sam Sample"), parent.id, true)
        val nonChild = MongoAcl(unrelatedObject.getId(), unrelatedObject::class.java.name, UUID.randomUUID().toString())

        val permission = DomainObjectPermission(UUID.randomUUID().toString(),
            MongoSid(SecurityContextHolder.getContext().authentication.name),
            BasePermission.READ.mask or BasePermission.WRITE.mask,
            true, true, true)

        parent.permissions = mutableListOf(permission)
        child1.permissions = mutableListOf(permission)
        child2.permissions = mutableListOf(permission)

        aclRepository.save(parent)
        aclRepository.save(child1)
        aclRepository.save(child2)
        aclRepository.save(child3)
        aclRepository.save(nonChild)

        val sids = listOf(PrincipalSid("Tim Test"), PrincipalSid("Sam Sample"))
        val identities = listOf(ObjectIdentityImpl(firstObject::class.java.name, firstObject.getId()),
            ObjectIdentityImpl(secondObject::class.java.name, secondObject.getId()),
            ObjectIdentityImpl(thirdObject::class.java.name, thirdObject.getId()))

        // Act & Assert
        val exception = assertThrows<NotFoundException> {
            aclService.readAclsById(identities, sids)
        }

        // You can perform additional assertions on the exception if needed
        assertNotNull(exception.message)
    }

    @Test
    @WithMockUser
    fun testReadAclsById_checkChildAclIsInheritingPermissions() {
        // Arrange
        val domainObject = TestDomainObject()
        val firstObject = TestDomainObject()
        val secondObject = TestDomainObject()
        val thirdObject = TestDomainObject()
        val unrelatedObject = TestDomainObject()

        val parent = MongoAcl(domainObject.getId(), domainObject::class.java.name, UUID.randomUUID().toString())
        val child1 = MongoAcl(firstObject.getId(), firstObject::class.java.name, UUID.randomUUID().toString(), MongoSid("Tim Test"), parent.id, true)
        val child2 = MongoAcl(secondObject.getId(), secondObject::class.java.name, UUID.randomUUID().toString(), MongoSid("Petty Pattern"), parent.id, true)
        val child3 = MongoAcl(thirdObject.getId(), thirdObject::class.java.name, UUID.randomUUID().toString(), MongoSid("Sam Sample"), parent.id, true)
        val nonChild = MongoAcl(unrelatedObject.getId(), unrelatedObject::class.java.name, UUID.randomUUID().toString())

        val permission = DomainObjectPermission(UUID.randomUUID().toString(), MongoSid(SecurityContextHolder.getContext().authentication.name), BasePermission.READ.mask or BasePermission.WRITE.mask, true, true, true)
        parent.permissions = mutableListOf(permission)
        child1.permissions = mutableListOf(permission)
        child2.permissions = mutableListOf(permission)

        aclRepository.save(parent)
        aclRepository.save(child1)
        aclRepository.save(child2)
        aclRepository.save(child3)
        aclRepository.save(nonChild)

        // Act
        val sids = listOf(PrincipalSid(SecurityContextHolder.getContext().authentication.name), PrincipalSid("Tim Test"))
        val objectIdentity = ObjectIdentityImpl(domainObject::class.java.name, domainObject.getId())
        val childObjects = aclService.findChildren(objectIdentity)
        val resultUser = aclService.readAclsById(childObjects, sids)

        // Assert
        assertTrue(resultUser.keys.size == 3)
    }
}
