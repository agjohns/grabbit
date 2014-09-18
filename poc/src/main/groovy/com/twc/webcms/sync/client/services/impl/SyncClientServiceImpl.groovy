package com.twc.webcms.sync.client.services.impl

import com.twc.webcms.sync.client.services.SyncClientService
import com.twc.webcms.sync.jcr.JcrUtil
import com.twc.webcms.sync.proto.NodeProtos
import com.twc.webcms.sync.proto.PreProcessorProtos
import com.twc.webcms.sync.client.unmarshaller.ProtobufUnmarshaller
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import org.apache.felix.scr.annotations.Activate
import org.apache.felix.scr.annotations.Component
import org.apache.felix.scr.annotations.Property as ScrProperty
import org.apache.felix.scr.annotations.Reference
import org.apache.felix.scr.annotations.Service
import org.apache.http.HttpEntity
import org.apache.http.HttpResponse
import org.apache.http.auth.AuthScope
import org.apache.http.auth.UsernamePasswordCredentials
import org.apache.http.client.CredentialsProvider
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.BasicCredentialsProvider
import org.apache.http.impl.client.DefaultHttpClient
import org.apache.sling.jcr.api.SlingRepository
import org.osgi.service.component.ComponentContext
import org.springframework.util.StopWatch

import javax.jcr.Session

@Slf4j
@CompileStatic
@Component(label = "Content Sync Client Service", description = "Content Sync Client Service", immediate = true, metatype = true, enabled = true)
@Service(SyncClientService)
@SuppressWarnings('GroovyUnusedDeclaration')
class SyncClientServiceImpl implements SyncClientService {

    @ScrProperty(label = "Sync Server Hostname", description = "Sync Server Hostname")
    public static final String SYNC_SERVER_HOSTNAME = "sync.server.hostname"
    private String syncServerHostname

    @ScrProperty(label = "Sync Server Port", description = "Sync Server Port")
    public static final String SYNC_SERVER_PORT = "sync.server.port"
    private String syncServerPort

    @ScrProperty(label = "Sync Server Username", description = "Sync Server Username")
    public static final String SYNC_SERVER_USERNAME = "sync.server.username"
    private String syncServerUsername

    @ScrProperty(label = "Sync Server Password", description = "Sync Server Password")
    public static final String SYNC_SERVER_PASSWORD = "sync.server.password"
    private String syncServerPassword

    @ScrProperty(label = "Sync Root Path", description = "Sync Root Path")
    public static final String SYNC_ROOT_PATH = "sync.root.path"
    private String syncRootPath

    @ScrProperty(boolValue = false, label = "Enable Data Sync")
    public static final String SYNC_ENABLED = "sync.enabled"
    private boolean syncEnabled

    @Reference(bind='setSlingRepository')
    SlingRepository slingRepository

    @Activate
    void activate(ComponentContext componentContext) {
        syncServerHostname = componentContext.properties[SYNC_SERVER_HOSTNAME] as String
        syncServerPort = componentContext.properties[SYNC_SERVER_PORT] as String
        syncServerUsername = componentContext.properties[SYNC_SERVER_USERNAME] as String
        syncServerPassword = componentContext.properties[SYNC_SERVER_PASSWORD] as String
        syncRootPath = componentContext.properties[SYNC_ROOT_PATH] as String
        syncEnabled = componentContext.properties[SYNC_ENABLED] as boolean

        if(syncEnabled) {
            doSync()
        }
    }

    void doSync() {
        final String SYNC_SERVER_URI = "/bin/twc/server/sync"
        final String syncPath = "http://${syncServerHostname}:${syncServerPort}${SYNC_SERVER_URI}?rootPath=${syncRootPath}"
        DefaultHttpClient client = new DefaultHttpClient()

        CredentialsProvider credentialsProvider = new BasicCredentialsProvider()
        credentialsProvider.setCredentials(
                new AuthScope(AuthScope.ANY_HOST, AuthScope.ANY_PORT),
                new UsernamePasswordCredentials(syncServerUsername, syncServerPassword)
        )
        client.setCredentialsProvider(credentialsProvider)
        //create the get request
        HttpGet get = new HttpGet(syncPath)

        try {
            withStopWatch {
                HttpResponse status = client.execute(get)
                HttpEntity responseEntity = status.entity
                ProtobufUnmarshaller protobufUnmarshaller = new ProtobufUnmarshaller()
                JcrUtil.withSession(slingRepository, "admin") { Session session ->

                    //Preprocessor step
                    //Receive and register all unknown namespaces first
                    PreProcessorProtos.Preprocessors preprocessors = PreProcessorProtos.Preprocessors.parseDelimitedFrom(responseEntity.content)
                    protobufUnmarshaller.fromPreprocessorsProto(preprocessors, session)

                    while (true) {
                        try{
                            NodeProtos.Node nodeProto = NodeProtos.Node.parseDelimitedFrom(responseEntity.content)
                            if(!nodeProto) {
                                session.save()
                                log.info "Received all data from Server for Sync. Completed unmarshalling. Total nodes : ${protobufUnmarshaller.nodeCount}"
                                break
                            }
                            protobufUnmarshaller.fromNodeProto(nodeProto, session)
                        }
                        catch (final Exception e) {
                            log.warn "Exception while unmarshalling received Protobuf", e
                            break
                        }
                    }
                }
            }
        }
        catch(Exception e) {
            log.error "Error while requesting a content sync for syncPath: ${syncPath}", e
        }
    }

    private <T> T withStopWatch(Closure<T> closure) {
        StopWatch stopWatch = new StopWatch("Content sync from ${syncServerHostname} for Content Path ${syncRootPath}")
        stopWatch.start()

        T retVal = closure.call()

        stopWatch.stop()
        log.info stopWatch.shortSummary()

        return retVal
    }

}
