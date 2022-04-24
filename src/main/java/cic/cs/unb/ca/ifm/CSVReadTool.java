package cic.cs.unb.ca.ifm;

import com.opencsv.CSVReader;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;

public class CSVReadTool {
    public static List<String[]> CSVRead(String str) throws IOException {
        String fileName = "data/out";
        fileName = fileName+"/"+str;
        CSVReader csvReader = null;
        DataInputStream in = new DataInputStream(new FileInputStream(fileName));
        csvReader = new CSVReader(new InputStreamReader(in,"utf-8"));
        List<String[]> list = csvReader.readAll();
        list.remove(0);
        for(int i=0;i<list.size();i++)
        {
            String[] csv_str = list.get(i);
            if(csv_str[0].contains("Flow"))
                list.remove(i);
        }
        return list;
    }
}
