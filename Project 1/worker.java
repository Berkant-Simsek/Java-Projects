package technology_store;

import java.util.Scanner;

public class worker extends humans {
	public String name_or_brand_name;
	protected String superscription;
	
	public worker(String name_or_brand_name, String superscription) {
		this.name_or_brand_name = name_or_brand_name;
		this.superscription = superscription;
	}

	public boolean sell() {
		System.out.print(this.superscription + " " + this.name_or_brand_name + " take or give the money? True/False ");
		Scanner ans = new Scanner(System.in);
		int x=1;
		while (x==1) {
			boolean ans1 = ans.nextBoolean();
			if (ans1==true) {
				System.out.println("Payment is sucsessful!");
				x=0;
				return ans1;
			}
			
			else if (ans1==false){
				System.out.println("Payment is NOT sucsessful!");
				x=0;
				return ans1;
			}
			
			else {
				System.out.println("Invalid entry!");
				System.out.print(this.superscription + " " + this.name_or_brand_name + " take or give the money? True/False ");
			}
		}
		return false;
	}
	
	
	
	@Override
	public void enter() {
		System.out.println(this.superscription + " " + this.name_or_brand_name + " serve to you.");
	}
	
}
