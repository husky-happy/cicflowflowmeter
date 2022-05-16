package com.web.controller;

import cic.cs.unb.ca.ifm.CICFlowMeter;
import cic.cs.unb.ca.ifm.CSVReadTool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.IOException;
import java.util.*;

@RestController
public class HandleController {
    @Autowired
    RestTemplate restTemplate;
    String[] Label = {"Src Port","Dst Port","Protocol","Flow Duration","Total Fwd Packet","Total Bwd packets","Total Length of Fwd Packet","Total Length of Bwd Packet","Fwd Packet Length Max","Fwd Packet Length Min","Fwd Packet Length Mean","Fwd Packet Length Std","Bwd Packet Length Max","Bwd Packet Length Min","Bwd Packet Length Mean","Bwd Packet Length Std","Flow Bytes/s","Flow Packets/s","Flow IAT Mean","Flow IAT Std","Flow IAT Max","Flow IAT Min","Fwd IAT Total","Fwd IAT Mean","Fwd IAT Std","Fwd IAT Max","Fwd IAT Min","Bwd IAT Total","Bwd IAT Mean","Bwd IAT Std","Bwd IAT Max","Bwd IAT Min","Fwd PSH Flags","Bwd PSH Flags","Fwd URG Flags","Bwd URG Flags","Fwd Header Length","Bwd Header Length","Fwd Packets/s","Bwd Packets/s","Packet Length Min","Packet Length Max","Packet Length Mean","Packet Length Std","Packet Length Variance","FIN Flag Count","SYN Flag Count","RST Flag Count","PSH Flag Count","ACK Flag Count","URG Flag Count","CWR Flag Count","ECE Flag Count","Down/Up Ratio","Average Packet Size","Fwd Segment Size Avg","Bwd Segment Size Avg","Fwd Bytes/Bulk Avg","Fwd Packet/Bulk Avg","Fwd Bulk Rate Avg","Bwd Bytes/Bulk Avg","Bwd Packet/Bulk Avg","Bwd Bulk Rate Avg","Subflow Fwd Packets","Subflow Fwd Bytes","Subflow Bwd Packets","Subflow Bwd Bytes","FWD Init Win Bytes","Bwd Init Win Bytes","Fwd Act Data Pkts","Fwd Seg Size Min","Active Mean","Active Std","Active Max","Active Min","Idle Mean","Idle Std","Idle Max","Idle Min"};
    int[] position ={2,4,5,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82};


    @GetMapping("/hello")
    public String hello(){
        return "hello";
    }

    @CrossOrigin
    @PostMapping("/upload")
    public Map<String,Object> fileupload(MultipartFile file){
        Map<String,Object> res = new HashMap<>();
        String originName = file.getOriginalFilename();
        if(!originName.endsWith(".pcap")){
            res.put("status","error");
            res.put("msg","文件类型不对");
        }
//        String path="D:\\project\\CICFlowMeter-master\\data\\in";
        String path = System.getProperty("user.dir");
        path = path + "\\data\\in";
        File folder=new File(path);
        String newName = UUID.randomUUID().toString()+".pcap";
        try{
            file.transferTo(new File(folder,newName));
            res.put("filename",newName);
            res.put("status","success");
        } catch (IOException e){
            e.printStackTrace();
            res.put("status","error");
            res.put("msg",e.getMessage());
        }
        return res;
    }


    @CrossOrigin
    @GetMapping("/analysePage")
    public Map<String,Object> analysePage(HttpServletRequest req) throws IOException{
        Map<String,Object> res = new HashMap<>();
        List<Map<String,Object>> tmp_res = new ArrayList<>() ;

        String pcapfile = req.getParameter("filename");
        int crPage = Integer.parseInt(req.getParameter("crPage"));
        int prSize = Integer.parseInt(req.getParameter("prSize"));
        CICFlowMeter ciciflowmeter = new CICFlowMeter();
        String CSVfile = ciciflowmeter.CSVHandling(pcapfile);
        CSVReadTool crd = new CSVReadTool();
        List<String[]> list = crd.CSVRead(CSVfile);
        for(int j=0;j<prSize;j++){
            int item = (crPage-1)*10+j;
            String[] csv_str = list.get(item);
            MultiValueMap<String, Object> a = new LinkedMultiValueMap<>();
            for(int i= 0;i<Label.length;i++){
                a.put(Label[i], Collections.singletonList(csv_str[position[i]]));
            }
            String url = "http://127.0.0.1:5000/modelHandle";
            Map<String,Object> res_p = restTemplate.postForObject(url,a,Map.class);
            String GBDT_pred= res_p.get("GBDT_pred").toString();
            String ATT_pred= res_p.get("ATT_pred").toString();
            double pred = Double.parseDouble(ATT_pred);
            String protocol = res_p.get("protocol").toString();
            ArrayList<Map<String,Object>> rule_dicts = (ArrayList<Map<String, Object>>) res_p.get("rule_dicts");
//            String tree = res_p.get("tree").toString();
//            String leaf = res_p.get("leaf").toString();
            String src_ip = csv_str[1];
            String dst_ip = csv_str[3];
            String src_port = csv_str[2];
            String dst_port = csv_str[4];
            String timestamp = csv_str[6];
            Map<String,Object> tableItem = new HashMap<>();
            tableItem.put("GBDT_pred",GBDT_pred);
            tableItem.put("ATT_pred",ATT_pred);
            tableItem.put("protocol",protocol);
            tableItem.put("rules",rule_dicts);
//            tableItem.put("tree",tree);
//            tableItem.put("leaf",leaf);
            tableItem.put("src_ip",src_ip);
            tableItem.put("dst_ip",dst_ip);
            tableItem.put("src_port",src_port);
            tableItem.put("dst_port",dst_port);
            tableItem.put("timestamp",timestamp);
            if(pred<0.5)
                tableItem.put("label","Normal");
            else
                tableItem.put("label","Attack");
            tmp_res.add(tableItem);
        }

        res.put("tableData",tmp_res);


        return res;
    }


    @CrossOrigin
    @GetMapping("/analyse")
    public Map<String,Object> analyse(HttpServletRequest req) throws IOException{
        Map<String,Object> res = new HashMap<>();
        String pcapfile = req.getParameter("filename");
        CICFlowMeter ciciflowmeter = new CICFlowMeter();
        String CSVfile = ciciflowmeter.CSVHandling(pcapfile);
        CSVReadTool crd = new CSVReadTool();
        List<String[]> list = crd.CSVRead(CSVfile);
        res.put("total",list.size());
        return res;
    }
}
