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
package org.springframework.security.acls.dao

import org.springframework.data.mongodb.repository.MongoRepository
import org.springframework.security.acls.domain.MongoAcl
import org.springframework.stereotype.Repository
import java.io.Serializable

/**
 * Spring Data MongoDB aclRepository for {@link MongoAcl} instances.
 *
 * @author Roman Vottner
 * @author Soumik Kumar Saha
 * @since 4.3
 */
@Repository
interface AclRepository : MongoRepository<MongoAcl, Serializable> {
    /**
     * Returns the ACL for a given domain object identifier and its class name.
     *
     * @param instanceId The unique identifier of the domain object the ACL should be returned for
     * @param className  The class name of the domain object referenced by the ACL
     * @return The access control list for the matching domain object.
     */
    fun findByInstanceIdAndClassName(
        instanceId: Serializable,
        className: String,
    ): List<MongoAcl>

    /**
     * Retrieves all child ACLs which specified the given <em>parentId</em> as their parent.
     *
     * @param parentId The unique identifier of the parent ACL
     * @return A list of child ACLs for the given parent ACL ID.
     */
    fun findByParentId(parentId: Serializable): List<MongoAcl>

    /**
     * Removes a document from the ACL collection that contains an instanceId field set to the provided value.
     *
     * @param instanceId The unique identifier of the domain object to remove an ACL entry for
     * @return The number of deleted documents
     */
    fun deleteByInstanceId(instanceId: Serializable): Long
}
