package com.twcable.grabbit.jcr

import com.twcable.grabbit.proto.NodeProtos.Node as ProtoNode
import com.twcable.grabbit.security.AuthorizablePrincipal
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import org.apache.jackrabbit.api.security.authorization.PrincipalSetPolicy
import org.apache.sling.jcr.base.util.AccessControlUtil

import javax.annotation.Nonnull
import javax.jcr.PathNotFoundException
import javax.jcr.Session
import javax.jcr.Value
import javax.jcr.security.AccessControlManager
import javax.jcr.security.AccessControlPolicy
import javax.jcr.security.AccessControlPolicyIterator
import java.security.Principal

/**
 * Wraps a rep:cugPolicy (rep:CugPolicy) node, providing the ability to write it
 */
@CompileStatic
@Slf4j
class CUGProtoNodeDecorator extends ProtoNodeDecorator {

    
    protected CUGProtoNodeDecorator(@Nonnull ProtoNode node, @Nonnull Collection<ProtoPropertyDecorator> protoProperties) {
        this.innerProtoNode = node
        this.protoProperties = protoProperties
    }


    @Override
    protected JCRNodeDecorator writeNode(@Nonnull Session session) {
        writeCUG(session)
        session.save()
        try {
            return new JCRNodeDecorator(session.getNode(getName()))
        } catch(PathNotFoundException ex) {
            //We may not have been able to write the policy node if for example the principal does not exist
            return new JCRNodeDecorator(session.getNode(parentPath))
        }
    }


    private void writeCUG(final Session session) {
        PrincipalSetPolicy cugPolicy = null
        AccessControlManager accessControlManager = getAccessControlManager(session)
        String parentPath = getParentPath()

        // try if there is a CugPolicy that has been set before
        for (AccessControlPolicy policy : accessControlManager.getPolicies(parentPath)) {
            if (policy instanceof PrincipalSetPolicy) {
                cugPolicy = (PrincipalSetPolicy) policy
                break
            }
        }
        // try if there is an applicable policy
        if (cugPolicy == null) {
            AccessControlPolicyIterator accessControlPolicyIterator = accessControlManager.getApplicablePolicies(parentPath)
            while (accessControlPolicyIterator.hasNext()) {
                AccessControlPolicy accessControlPolicy = accessControlPolicyIterator.nextAccessControlPolicy()
                if (accessControlPolicy instanceof PrincipalSetPolicy) {
                    cugPolicy = (PrincipalSetPolicy) accessControlPolicy
                    break
                }
            }
        }

        if (cugPolicy != null) {
            final Principal[] principals = getPrincipals()
            cugPolicy.addPrincipals(principals)
            accessControlManager.setPolicy(parentPath, cugPolicy)
        }
        else {
            log.warn "Unable to find an existing or applicable policy for '${parentPath}'. Can not write CUG information."
        }
    }


    private AccessControlManager getAccessControlManager(final Session session) {
        return AccessControlUtil.getAccessControlManager(session)
    }


    private Principal[] getPrincipals() {
        final ProtoPropertyDecorator principalsProperty = innerProtoNode.propertiesList.collect { new ProtoPropertyDecorator(it) }.find { ProtoPropertyDecorator property ->
            property.isPrincipalNames()
        }
        return principalsProperty.getPropertyValues().collect { Value value -> new AuthorizablePrincipal(value.string) }.toArray() as Principal[]
    }

}
