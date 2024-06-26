package org.springframework.security.acls

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class SpringSecurityAclMongodbKotlinApplication

fun main(args: Array<String>) {
	runApplication<SpringSecurityAclMongodbKotlinApplication>(*args)
}
