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

/**
 * Represents a security identity assignable to certain permissions in an access control list. The identity can either
 * be a user principal or a granted authority. If {@link #isPrincipal} returns true, the security identity represents an
 * authenticated user, otherwise an instance of this class will represent a granted authority.
 *
 * @author Roman Vottner
 * @author Soumik Kumar Saha
 * @since 4.3
 */
class MongoSid(
    /**
     * The name of the security identity
     **/
    var name: String,
    /**
     * Defines whether this security identity is a user principal (true) or a granted authority (false)
     **/
    var isPrincipal: Boolean = true,
) {
    override fun toString(): String = "MongoSid[name = $name, isPrincipal = $isPrincipal]"
}
